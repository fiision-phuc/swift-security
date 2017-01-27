//  Project name: FwiSecurity
//  File name   : FwiKey.swift
//
//  Author      : Phuc, Tran Huu
//  Created date: 1/19/17
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

import CommonCrypto
import Foundation
/// Optional
import FwiCore


internal struct FwiKey {

    // MARK: Class's constructors
    internal init() {
        identifier = "com.fiision.lib.key"
        size = 0
        
        attributes = [
            SecAttr.atag.value:identifier.toData() ?? Data(),
            "\(kSecClass)":kSecClassKey,
            SecAttr.bsiz.value:size,
            SecAttr.esiz.value:size,
            SecAttr.crtr.value:kCFBooleanFalse,
            SecAttr.decr.value:kCFBooleanFalse,
            SecAttr.drve.value:kCFBooleanFalse,
            SecAttr.encr.value:kCFBooleanFalse,
            SecAttr.kcls.value:kCFBooleanFalse,
            SecAttr.perm.value:kCFBooleanTrue,
            SecAttr.sign.value:kCFBooleanFalse,
            SecAttr.unwp.value:kCFBooleanFalse,
            SecAttr.vrfy.value:kCFBooleanFalse,
            SecAttr.wrap.value:kCFBooleanFalse
        ]
    }
    internal init(withIdentifier i: String?) {
        self.init()
        
        // Update key's attributes
        if let i = i, let data = i.toData() {
            attributes[SecAttr.atag.value] = data
            identifier = i
        }
        
        // 1. Query key entry
        let query: [String:Any] = [SecAttr.atag.value:(attributes[SecAttr.atag.value] ?? Data()),
                                   "\(kSecClass)":(attributes["\(kSecClass)"] ?? kSecClassKey),
                                   "\(kSecReturnPersistentRef)":kCFBooleanTrue,
                                   "\(kSecReturnData)":kCFBooleanFalse]
        
        var status = SecItemCopyMatching(query as CFDictionary, &entry)
        
        // 2. Query key's attributes
        if let entry = entry, status == errSecSuccess {
            var attrRef: AnyObject?
            defer { attrRef = nil }
            
            let attrQuery: [String:Any] = ["\(kSecValuePersistentRef)":entry,
                                           "\(kSecReturnAttributes)":kCFBooleanTrue]
        
            status = SecItemCopyMatching(attrQuery as CFDictionary, &attrRef)
            
            // Update key's attributes & key's size
            if let dictionary = attrRef as? [String:Any], let s = dictionary[SecAttr.bsiz.value] as? Int, status == errSecSuccess {
                attributes = dictionary
                size = s
            }
        }
    }
    
    // MARK: Class's properties
    internal var attributes: [String:Any]
    internal var identifier: String {
        didSet {
            /* Condition validation */
            guard let identifierData = identifier.toData() else {
                return
            }
            attributes[SecAttr.atag.value] = identifierData
            
            /* Condition validation: validate if  */
            guard let entry = entry else {
                return
            }
            let query: [String:Any] = ["\(kSecValuePersistentRef)":entry]
            let newInfo: [String:Any] = [SecAttr.atag.value:identifierData]
            let status = SecItemUpdate(query as CFDictionary, newInfo as CFDictionary)
            
            if status == errSecSuccess {
                FwiLog("[INFO] Success update '\(identifier)' key inside keystore!")
            } else {
                FwiLog("[ERROR] Could not update '\(identifier)' key inside keystore!")
            }
        }
    }
    internal var size: Int {
        didSet {
            attributes[SecAttr.bsiz.value] = size
            attributes[SecAttr.esiz.value] = size
        }
    }
    
    internal var entry: AnyObject?
    
    // MARK: Class's internal methods
    /// Remove this key from keystore.
    internal func remove() {
        let keyInfo: [String:Any] = ["\(kSecClass)":(attributes["\(kSecClass)"] ?? kSecClassKey),
                                     SecAttr.atag.value:(identifier.toData() ?? Data())]
        
        var status: OSStatus
        repeat {
            status = SecItemDelete(keyInfo as CFDictionary)
        } while (status == errSecSuccess)
    }
    
    /// Insert this key into keystore.
    ///
    /// - parameter data (required): key's data
    internal mutating func save(withData d: Data) {
        size = d.count
        
        guard let e = entry else {
            var keyInfo = attributes
            keyInfo["\(kSecValueData)"] = d
            keyInfo["\(kSecReturnPersistentRef)"] = kCFBooleanTrue
            
            let status = SecItemAdd(keyInfo as CFDictionary, &entry)
            if status == errSecSuccess {
                FwiLog("[INFO] Success insert '\(identifier)' key into keystore!")
            } else {
                FwiLog("[ERROR] Could not insert '\(identifier)' key into keystore!")
            }
            return
        }
        
        let query: [String:Any] = ["\(kSecValuePersistentRef)":e]
        let newInfo: [String:Any] = ["\(kSecValueData)":d,
                                     SecAttr.bsiz.value:size,
                                     SecAttr.esiz.value:size]
        let status = SecItemUpdate(query as CFDictionary, newInfo as CFDictionary)
        
        if status == errSecSuccess {
            FwiLog("[INFO] Success update '\(identifier)' key inside keystore!")
        } else {
            FwiLog("[ERROR] Could not update '\(identifier)' key inside keystore!")
        }
    }

    /// Convert to raw data.
    internal func encode() -> Data? {
        guard let entry = entry else {
            return nil
        }
        
        var dataRef: AnyObject?
        defer { dataRef = nil }
        
        let keyInfo: [String:Any] = ["\(kSecValuePersistentRef)":entry, "\(kSecReturnData)":kCFBooleanTrue]
        let status = SecItemCopyMatching(keyInfo as CFDictionary, &dataRef)
        
        if let data = dataRef as? Data, status == errSecSuccess {
            return data
        }
        return nil
    }
    
    /// Convert raw data to base64 data.
    internal func encodeBase64Data() -> Data? {
        return encode()?.encodeBase64Data()
    }
    
    /// Convert raw data to base64 string.
    internal func encodeBase64String() -> String? {
        return encodeBase64Data()?.toString()
    }
}
