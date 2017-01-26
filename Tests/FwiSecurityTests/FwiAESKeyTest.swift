//  Project name: FwiSecurity
//  File name   : FwiAESKeyTest.swift
//
//  Author      : Phuc, Tran Huu
//  Created date: 1/24/17
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


class FwiAESKeyTest: XCTestCase {
    
    
    fileprivate var key: FwiAESKey?
    
    
    // MARK: Setup
    override func setUp() {
        super.setUp()
        key = FwiAESKey(withSize: .size128)
    }
    
    // MARK: Tear Down
    override func tearDown() {
        key?.remove()
        super.tearDown()
    }
    
    // MARK: Test Cases
    func testEncryptWithoutIV() {
        let data = "Hello World".toData()
        
        let encryptedData = key?.encrypt(data: data)
        let decryptedData = key?.decrypt(data: encryptedData)
        
        XCTAssertNil(key?.iv, "Expected not nil.")
        XCTAssertNotNil(decryptedData, "Expected not nil.")
        XCTAssertNotNil(encryptedData, "Expected not nil.")
        XCTAssertEqual(decryptedData?.toString(), data?.toString(), "Expected '\(data?.toString())' but found: '\(decryptedData?.toString())'.")
    }
    
    func testEncryptWithIV() {
        let data = "Hello World".toData()
        
        let encryptedData = key?.encrypt(data: data, enableIV: true)
        let decryptedData = key?.decrypt(data: encryptedData)
        
        XCTAssertNotNil(key?.iv, "Expected not nil.")
        XCTAssertNotNil(decryptedData, "Expected not nil.")
        XCTAssertNotNil(encryptedData, "Expected not nil.")
        XCTAssertEqual(decryptedData?.toString(), data?.toString(), "Expected '\(data?.toString())' but found: '\(decryptedData?.toString())'.")
    }
}
