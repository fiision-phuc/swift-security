//  Project name: FwiSecurity
//  File name   : FwiRSAKeypair.swift
//
//  Author      : Phuc, Tran Huu
//  Created date: 1/26/17
//  Version     : 1.00
//  --------------------------------------------------------------
//  Copyright © 2017 Fiision Studio. All rights reserved.
//  --------------------------------------------------------------

import Foundation
/// Optional
import FwiCore


public struct FwiRSAKeypair {

    // MARK: Class's constructors
    public init?(withIdentifier i: String? = String.randomIdentifier()) {
        guard let identifier = i, identifier.length() > 0 else {
            return nil
        }
        
        let pubIdentifier = "\(identifier)|pub"
        let pvtIdentifier = "\(identifier)|pvt"
        publicKey = FwiRSAPublicKey(withIdentifier: pubIdentifier)
        privateKey = FwiRSAPrivateKey(withIdentifier: pvtIdentifier)
    }
    public init?(withIdentifier i: String? = String.randomIdentifier(), keySize s: FwiRSASize) {
        guard let identifier = i, identifier.length() > 0 else {
            return nil
        }
        let pubIdentifier = "\(identifier)|pub"
        let pvtIdentifier = "\(identifier)|pvt"
        
        /* Condition validation: validate public's identifier & private's identifier */
        guard let pubID = pubIdentifier.toData(), let pvtID = pvtIdentifier.toData() else {
            return nil
        }
        
        // Remove all keys that are associated with these identifier
        var keyInfo: [String:Any] = ["\(kSecClass)":kSecClassKey, SecAttr.atag.value:pubID]
        var status: OSStatus
        
        // Remove all public keys that have similar identifier
        repeat {
            status = SecItemDelete(keyInfo as CFDictionary)
        } while (status == errSecSuccess)
        
        // Remove all private keys that have similar identifier
        keyInfo = ["\(kSecClass)":kSecClassKey, SecAttr.atag.value:pvtID]
        repeat {
            status = SecItemDelete(keyInfo as CFDictionary)
        } while (status == errSecSuccess)
        
        // Define attributes
        let pvtAttributes: [String:Any] = [SecAttr.atag.value:pvtID, SecAttr.perm.value:kCFBooleanTrue]
        let pubAttributes: [String:Any] = [SecAttr.atag.value:pubID, SecAttr.perm.value:kCFBooleanTrue]
        let kpAttributes: [String:Any]  = [SecAttr.bsiz.value:s.rawValue,
                                           SecAttr.type.value:kSecAttrKeyTypeRSA,
                                           "\(kSecPublicKeyAttrs)":pubAttributes,
                                           "\(kSecPrivateKeyAttrs)":pvtAttributes]
        
        var pubKeyRef: SecKey?
        var pvtKeyRef: SecKey?
        defer {
            pubKeyRef = nil
            pvtKeyRef = nil
        }
        
        status = SecKeyGeneratePair(kpAttributes as CFDictionary, &pubKeyRef, &pvtKeyRef)
        if status == errSecSuccess {
            publicKey = FwiRSAPublicKey(withIdentifier: pubIdentifier)
            privateKey = FwiRSAPrivateKey(withIdentifier: pvtIdentifier)
        }
    }
    
    // MARK: Class's properties
    public fileprivate(set) var publicKey: FwiRSAPublicKey?
    public fileprivate(set) var privateKey: FwiRSAPrivateKey?
    
    // MARK: Class's public methods
    public func createCSR(WithSubject s: [String:Any], digest d: FwiDigest = .sha1) -> String? {
        return nil
    }
    
    // MARK: Class's private methods
}
