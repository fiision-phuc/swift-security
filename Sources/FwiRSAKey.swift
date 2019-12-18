//  Project name: FwiSecurity
//  File name   : FwiRSAKey.swift
//
//  Author      : Phuc, Tran Huu
//  Created date: 1/26/17
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

import Foundation
/// Optional
import FwiCore


internal struct FwiRSAKey {

    // MARK: Class's constructors
    internal init(withIdentifier i: String? = String.randomIdentifier) {
        key = FwiKey(withIdentifier: i)
        
        // Indentify key's attributes
        if key.entry == nil {
            key.attributes[SecAttr.klbl.value] = "K3oWETTJGjEui1w+FpWTpoh0dAg=".decodeBase64Data() ?? Data()
            key.attributes[SecAttr.type.value] = 42
            key.attributes[SecAttr.asen.value] = kCFBooleanFalse
            key.attributes[SecAttr.decr.value] = kCFBooleanTrue
            key.attributes[SecAttr.drve.value] = kCFBooleanTrue
            key.attributes[SecAttr.extr.value] = kCFBooleanTrue
            key.attributes[SecAttr.modi.value] = kCFBooleanTrue
            key.attributes[SecAttr.next.value] = kCFBooleanFalse
            key.attributes[SecAttr.priv.value] = kCFBooleanTrue
            key.attributes[SecAttr.sens.value] = kCFBooleanFalse
            key.attributes[SecAttr.sign.value] = kCFBooleanTrue
            key.attributes[SecAttr.snrc.value] = kCFBooleanFalse
            key.attributes[SecAttr.unwp.value] = kCFBooleanTrue
            key.attributes[SecAttr.vyrc.value] = kCFBooleanFalse
        }
    }
    
    // MARK: Class's properties
    internal var objectIdentifier: String {
        return "1.2.840.113549.1.1.1"
    }
    internal var version: Int8 {
        return 2
    }
    
    internal var inKeystore: Bool {
        return key.entry != nil
    }
    internal var keyRef: (SecKey?, Int) {
        /* Condition validation */
        guard let entry = key.entry else {
            return (nil, 0)
        }

        var k: AnyObject?
        defer { k = nil }

        let query: [String:Any] = ["\(kSecValuePersistentRef)":entry, "\(kSecReturnRef)":kCFBooleanTrue]
        let status = SecItemCopyMatching(query as CFDictionary, &k)

        if let keyRef = k, status == errSecSuccess {
            let blocksize = SecKeyGetBlockSize(keyRef as! SecKey)
            return ((keyRef as! SecKey), blocksize)
        }
        return (nil, 0)
    }
    
    internal var key: FwiKey
}
