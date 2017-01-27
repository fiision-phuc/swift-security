import XCTest
@testable import FwiSecurity

class FwiSecurityTests: XCTestCase {
    
    func testExample() {
//        let kp = FwiRSAKeypair(keySize: .size1024)
        let kp = FwiRSAKeypair(withIdentifier: "D121163B-8E21-489E-9B23-F73011C246CA")
        XCTAssertEqual("", "Hello, World!")
    }


    static var allTests : [(String, (FwiSecurityTests) -> () throws -> Void)] {
        return [
            ("testExample", testExample),
        ]
    }
}
