//  Project name: FwiSecurity
//  File name   : FwiKeyTest.swift
//
//  Author      : Phuc, Tran Huu
//  Created date: 1/23/17
//  Version     : 1.00
//  --------------------------------------------------------------
//  Copyright © 2012, 2017 Fiision Studio.
//  All Rights Reserved.
//  --------------------------------------------------------------
//
//  Permission is hereby granted, free of charge, to any person obtaining  a  copy
//  of this software and associated documentation files (the "Software"), to  deal
//  in the Software without restriction, including without limitation  the  rights
//  to use, copy, modify, merge,  publish,  distribute,  sublicense,  and/or  sell
//  copies of the Software,  and  to  permit  persons  to  whom  the  Software  is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in all
//  copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF  ANY  KIND,  EXPRESS  OR
//  IMPLIED, INCLUDING BUT NOT  LIMITED  TO  THE  WARRANTIES  OF  MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO  EVENT  SHALL  THE
//  AUTHORS OR COPYRIGHT HOLDERS  BE  LIABLE  FOR  ANY  CLAIM,  DAMAGES  OR  OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING  FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN  THE
//  SOFTWARE.
//
//
//  Disclaimer
//  __________
//  Although reasonable care has been taken to  ensure  the  correctness  of  this
//  software, this software should never be used in any application without proper
//  testing. Fiision Studio disclaim  all  liability  and  responsibility  to  any
//  person or entity with respect to any loss or damage caused, or alleged  to  be
//  caused, directly or indirectly, by the use of this software.

import XCTest
@testable import FwiSecurity


class FwiKeyTest: XCTestCase {
    
    // MARK: Setup
    override func setUp() {
        super.setUp()
    }
    
    // MARK: Tear Down
    override func tearDown() {
        super.tearDown()
    }
    
    // MARK: Test Cases
    func testInit() {
        let key = FwiKey()
        
        XCTAssertEqual(key.identifier, "com.fiision.lib.key", "Expected 'com.fiision.lib.key' but found: '\(key.identifier)'.")
        XCTAssertEqual(key.size, 0, "Expected '0' but found: '\(key.size)'")
        
        if let identifierData = key.attributes[SecAttr.atag.value] as? Data, let identifier = identifierData.toString() {
            XCTAssertEqual(identifier, "com.fiision.lib.key", "Expected 'com.fiision.lib.key' but found: '\(identifier)'.")
        } else {
            XCTFail("Expected key's identifier not null.")
        }
        
        if let size = key.attributes[SecAttr.bsiz.value] as? Int {
            XCTAssertEqual(size, 0, "Expected '0' but found: '\(size)'.")
        } else {
            XCTFail("Expected key's size not null.")
        }
        if let size = key.attributes[SecAttr.esiz.value] as? Int {
            XCTAssertEqual(size, 0, "Expected '0' but found: '\(size)'.")
        } else {
            XCTFail("Expected key's size not null.")
        }
    }
    
    func testInitWithIdentifier() {
        let identifier = String.randomIdentifier()
        let key = FwiKey(withIdentifier: identifier)
        
        XCTAssertEqual(key.identifier, identifier, "Expected '\(identifier)' but found: '\(key.identifier)'.")
        XCTAssertEqual(key.size, 0, "Expected '0' but found: '\(key.size)'.")
        
        if let identifierData = key.attributes[SecAttr.atag.value] as? Data, let identifier = identifierData.toString() {
            XCTAssertEqual(identifier, identifier, "Expected 'com.fiision.lib.key' but found: '\(identifier)'.")
        } else {
            XCTFail("Expected key's identifier not null.")
        }
        
        if let size = key.attributes[SecAttr.bsiz.value] as? Int {
            XCTAssertEqual(size, 0, "Expected '0' but found: '\(size)'.")
        } else {
            XCTFail("Expected key's size not null.")
        }
        if let size = key.attributes[SecAttr.esiz.value] as? Int {
            XCTAssertEqual(size, 0, "Expected '0' but found: '\(size)'.")
        } else {
            XCTFail("Expected key's size not null.")
        }
    }
    
    func testRemove() {
        let identifier = String.randomIdentifier()
        var key = FwiKey(withIdentifier: identifier)
        
        // Generate data
        var keyBytes = [UInt8](repeating: 0, count: FwiAESSize.size128.length)
        _ = SecRandomCopyBytes(kSecRandomDefault, FwiAESSize.size128.length, &keyBytes)
        
        let originData = Data(bytes: keyBytes)
        key.save(withData: originData)
        
        // Query key first time
        let query: [String:Any] = [SecAttr.atag.value:(identifier?.toData() ?? Data()),
                                   "\(kSecClass)":kSecClassKey,
                                   "\(kSecReturnPersistentRef)":kCFBooleanTrue,
                                   "\(kSecReturnData)":kCFBooleanFalse]
        
        var entry: AnyObject?
        defer { entry = nil }
        
        var status = SecItemCopyMatching(query as CFDictionary, &entry)
        XCTAssertEqual(status, errSecSuccess, "Expected '\(errSecSuccess)' but found: '\(status)'.")
        
        // Remove
        key.remove()
        status = SecItemCopyMatching(query as CFDictionary, &entry)
        XCTAssertEqual(status, errSecItemNotFound, "Expected '\(errSecItemNotFound)' but found: '\(status)'.")
    }
    
    func testSave() {
        var key = FwiKey(withIdentifier: "F377D13C-6BBB-4136-8BA4-30FE52816423")
        defer { key.remove() }
        
        // Generate data
        var keyBytes = [UInt8](repeating: 0, count: FwiAESSize.size128.length)
        _ = SecRandomCopyBytes(kSecRandomDefault, FwiAESSize.size128.length, &keyBytes)
        
        let originData = Data(bytes: keyBytes)
        key.save(withData: originData)
        
        let keyData = key.encode()
        XCTAssertEqual(keyData, originData, "Expected '\(originData.encodeHexData())' but found: '\(keyData?.encodeHexData())'.")
        
        // Query key first time
        let query: [String:Any] = [SecAttr.atag.value:(key.identifier.toData() ?? Data()),
                                   "\(kSecClass)":kSecClassKey,
                                   "\(kSecReturnPersistentRef)":kCFBooleanTrue,
                                   "\(kSecReturnData)":kCFBooleanFalse]
        
        var entry: AnyObject?
        defer { entry = nil }
        
        let status = SecItemCopyMatching(query as CFDictionary, &entry)
        XCTAssertEqual(status, errSecSuccess, "Expected '\(errSecSuccess)' but found: '\(status)'.")
    }
    
    func testUpdate() {
        let identifier = String.randomIdentifier()
        var key = FwiKey(withIdentifier: identifier)
        defer { key.remove() }
        
        // Generate data
        var keyBytes = [UInt8](repeating: 0, count: FwiAESSize.size128.length)
        _ = SecRandomCopyBytes(kSecRandomDefault, FwiAESSize.size128.length, &keyBytes)
        
        let originData = Data(bytes: keyBytes)
        key.save(withData: originData)
        
        XCTAssertEqual(key.size, FwiAESSize.size128.length, "Expected '\(FwiAESSize.size128.length)' but found: '\(key.size)'.")
        if let size = key.attributes[SecAttr.bsiz.value] as? Int {
            XCTAssertEqual(size, FwiAESSize.size128.length, "Expected '\(FwiAESSize.size128.length)' but found: '\(size)'.")
        } else {
            XCTFail("Expected key's size not null.")
        }
        if let size = key.attributes[SecAttr.esiz.value] as? Int {
            XCTAssertEqual(size, FwiAESSize.size128.length, "Expected '\(FwiAESSize.size128.length)' but found: '\(size)'.")
        } else {
            XCTFail("Expected key's size not null.")
        }
        
        // Update new data
        keyBytes = [UInt8](repeating: 0, count: FwiAESSize.size256.length)
        _ = SecRandomCopyBytes(kSecRandomDefault, FwiAESSize.size256.length, &keyBytes)
        let nextData = Data(bytes: keyBytes)
        key.save(withData: nextData)
        
        let keyData = key.encode()
        XCTAssertEqual(keyData, nextData, "Expected '\(nextData.encodeHexData())' but found: '\(keyData?.encodeHexData())'.")
        
        if let size = key.attributes[SecAttr.bsiz.value] as? Int {
            XCTAssertEqual(size, FwiAESSize.size256.length, "Expected '\(FwiAESSize.size256.length)' but found: '\(size)'.")
        } else {
            XCTFail("Expected key's size not null.")
        }
        if let size = key.attributes[SecAttr.esiz.value] as? Int {
            XCTAssertEqual(size, FwiAESSize.size256.length, "Expected '\(FwiAESSize.size256.length)' but found: '\(size)'.")
        } else {
            XCTFail("Expected key's size not null.")
        }
        
        // Update key's identifier
        key.identifier = "F377D13C-6BBB-4136-8BA4-30FE52816423"
        
        // Validate against second key
        let secondKey = FwiKey(withIdentifier: "F377D13C-6BBB-4136-8BA4-30FE52816423")
        if let size = secondKey.attributes[SecAttr.bsiz.value] as? Int {
            XCTAssertEqual(size, FwiAESSize.size256.length, "Expected '\(FwiAESSize.size256.length)' but found: '\(size)'.")
        } else {
            XCTFail("Expected key's size not null.")
        }
        if let size = secondKey.attributes[SecAttr.esiz.value] as? Int {
            XCTAssertEqual(size, FwiAESSize.size256.length, "Expected '\(FwiAESSize.size256.length)' but found: '\(size)'.")
        } else {
            XCTFail("Expected key's size not null.")
        }
    }
}
