import XCTest
@testable import FwiSecurity

class FwiSecurityTests: XCTestCase {
    func testExample() {
        // This is an example of a functional test case.
        // Use XCTAssert and related functions to verify your tests produce the correct results.
        XCTAssertEqual(FwiSecurity().text, "Hello, World!")
    }


    static var allTests : [(String, (FwiSecurityTests) -> () throws -> Void)] {
        return [
            ("testExample", testExample),
        ]
    }
}
