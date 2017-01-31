import XCTest
@testable import FwiSecurity

class FwiSecurityTests: XCTestCase {
    
    func testExample() {
//        let text = "Motus TechNolo"
        let text = "129874591347203948n 02348039471023710239481203948 10394810394830749"
        let oid = FwiDER.objectIdentifier(withString: FwiDigest.sha512.signatureOID)
        print("\(oid.content?.encodeHexString())")
        let string = oid.objectIdentifier
        
//        let c = Character(UnicodeScalar(72))
//        let lowerBound = Character("0")
//        let upperBound
        let isValid = text.toData()?.reduce(true, { (currentFlag, unit) -> Bool in
            guard currentFlag else {
                return false
            }
            let c = Character(UnicodeScalar(unit))
            return (("0" <= c && c <= "9") || c == " ")
        })
        let data = text.utf16.reduce(Data(), { (bmpString, unit) -> Data in
            let b1 = UInt8((unit & 0xff00) >> 8)
            let b2 = UInt8(unit & 0x00ff)
            var string = bmpString
            
            string.append(b1)
            string.append(b2)
            return string
        })
        XCTAssertEqual("", "Hello, World!")
        let der = FwiDER.bitString()
        let child = der[0]
        let child2 = der["1"]
    }


    static var allTests : [(String, (FwiSecurityTests) -> () throws -> Void)] {
        return [
            ("testExample", testExample),
        ]
    }
}
