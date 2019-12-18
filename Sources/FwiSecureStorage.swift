//  Project name: FwiSecurity
//  File name   : FwiSecureStorage.swift
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


public final class FwiSecureStorage {
    // MARK: Singleton instance
    public static let instance = FwiSecureStorage()
    
    // MARK: Class's constructors
    fileprivate init() {
    }
    
    // MARK: Class's properties
    fileprivate lazy var key: FwiAESKey = {
        guard let identifier = UserDefaults.standard.object(forKey: "secureStorage") as? String, identifier.count > 0 else {
            preconditionFailure("Could not find value for: 'secureStorage' inside UserDefaults.standard")
        }
        
        var key = FwiAESKey(withIdentifier: identifier)
        if !key.inKeystore {
            key = FwiAESKey(withIdentifier: identifier, keySize: .size256)
        }
        return key
    }()
    fileprivate lazy var preferences: [String:Any] = {
        let userDefaults = UserDefaults.standard
        
        // Decrypt data
        guard let data = userDefaults.object(forKey: "preferences") as? Data else {
            return [String:Any]()
        }
        
        // Try to restore previous preferences
        guard let decryptedData = self.key.decrypt(data: data), let d = NSKeyedUnarchiver.unarchiveObject(with: decryptedData) as? [String:Any] else {
            return [String:Any]()
        }
        return d
    }()
    
    // MARK: Class's public methods
    public subscript(key: String) -> Any? {
        get {
            return preferences[key]
        }
        set {
            /* Condition validation */
            if key.count == 0 {
                return
            }
            objc_sync_enter(preferences); defer { objc_sync_exit(preferences) }
            
            if let value = newValue {
                preferences[key] = value
            } else {
                preferences.removeValue(forKey: key)
            }
        }
    }
    
    /// Save user's preference to UserDefaults. The save function requires a lot of resources from
    /// device, only sensity info must be persisted right away, otherwise, should only perform save
    /// function when everything is finished.
    public func save() {
        objc_sync_enter(preferences); defer { objc_sync_exit(preferences) }
        
        // Encrypted data
        let data = NSKeyedArchiver.archivedData(withRootObject: preferences)
        guard let encryptedData = key.encrypt(data: data) else {
            return
        }
        let userDefaults = UserDefaults.standard
        
        // Save encrypted data
        userDefaults.set(encryptedData, forKey: "preferences")
        userDefaults.synchronize()
    }
}
