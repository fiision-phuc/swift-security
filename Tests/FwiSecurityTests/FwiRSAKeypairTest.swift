//  Project name: FwiSecurity
//  File name   : FwiRSAKeypairTest.swift
//
//  Author      : Phuc, Tran Huu
//  Created date: 1/28/17
//  Version     : 1.00
//  --------------------------------------------------------------
//  Copyright © 2017 Fiision Studio. All rights reserved.
//  --------------------------------------------------------------

import XCTest
@testable import FwiSecurity


class FwiRSAKeypairTest: XCTestCase {
    
    // MARK: Setup
    override func setUp() {
        super.setUp()
    }
    
    // MARK: Tear Down
    override func tearDown() {
        super.tearDown()
    }
    
    // MARK: Test Cases
    func testCreate() {
        let kp1 = FwiRSAKeypair(keySize: .size1024)
        XCTAssertNotNil(kp1?.publicKey, "Expected not nil but found nil.")
        XCTAssertNotNil(kp1?.privateKey, "Expected not nil but found nil.")
        
        let kp2 = FwiRSAKeypair(withIdentifier: kp1?.identifier)
        XCTAssertNotNil(kp2?.publicKey, "Expected not nil but found nil.")
        XCTAssertNotNil(kp2?.privateKey, "Expected not nil but found nil.")
        
        kp1?.remove()
        let kp3 = FwiRSAKeypair(withIdentifier: kp1?.identifier)
        XCTAssertNil(kp3?.publicKey, "Expected nil but found not nil.")
        XCTAssertNil(kp3?.privateKey, "Expected nil but found not nil.")
    }
    
    func testEncryptAndDecrypt() {
        let kp = FwiRSAKeypair(keySize: .size1024)
        defer { kp?.remove() }
        
        let encryptedData = kp?.publicKey?.encrypt(data: "Hello, World!".toData())
        let signature = kp?.privateKey?.sign(encryptedData: "Hello, World!".toData(), usingDigest: .sha512)
        XCTAssertEqual(encryptedData?.count, 128, "Expected '128' but found: '\(encryptedData?.count)'.")
        XCTAssertEqual(signature?.count, 128, "Expected '128' but found: '\(signature?.count)'.")
        
        let decryptedData = kp?.privateKey?.decrypt(data: encryptedData)
        XCTAssertTrue(kp?.publicKey?.verify(data: decryptedData, usingDigest: .sha512, withSignature: signature) ?? false, "Expected 'true' but found: 'false'.")
        XCTAssertEqual(decryptedData?.toString(), "Hello, World!", "Expected 'Hello, World!' but found: '\(decryptedData?.toString())'.")
    }
}
