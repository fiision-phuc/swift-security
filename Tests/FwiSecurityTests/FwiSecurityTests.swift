import XCTest
@testable import FwiSecurity

class FwiSecurityTests: XCTestCase {
    
    func testExample() {
        XCTAssertEqual("", "Hello, World!")
    }


    static var allTests : [(String, (FwiSecurityTests) -> () throws -> Void)] {
        return [
            ("testExample", testExample),
        ]
    }
}
