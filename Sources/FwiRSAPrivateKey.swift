//  Project name: FwiSecurity
//  File name   : FwiRSAPrivateKey.swift
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


public struct FwiRSAPrivateKey {

    // MARK: Class's constructors
    public init?(withIdentifier i: String? = String.randomIdentifier()) {
        guard let identifier = i, identifier.length() > 0 else {
            return nil
        }
        
        rsaKey = FwiRSAKey(withIdentifier: "\(identifier)|private")
        guard rsaKey.inKeystore else {
            return nil
        }
    }
    
    // MARK: Class's properties
    fileprivate var rsaKey: FwiRSAKey
    
    // MARK: Class's public methods
    /// Decrypt Data.
    ///
    /// - parameter data (required): data to be decrypted
    public func decrypt(data d: Data?) -> Data? {
        var (keyRef, blocksize) = rsaKey.keyRef
        
        /* Condition validation */
        guard let key = keyRef, let data = d, data.count == blocksize else {
            return nil
        }
        
        // Decrypt data
        var buffer = [UInt8](repeating: 0, count: blocksize)
        defer { bzero(&buffer, buffer.count) }
        
        // Finalize result
        let status = SecKeyDecrypt(key, .PKCS1, data.bytes(), data.count, &buffer, &blocksize)
        if status != errSecSuccess {
            return nil
        }
        return Data(bytes: buffer, count: blocksize)
    }
    
    /// Generate signature for encrypted data.
    ///
    /// - parameter data (required): data to be encrypted
    /// - parameter digest (required): digest to create signature
    public func sign(encryptedData da: Data?, usingDigest di: FwiDigest = .sha1) -> Data? {
        var (keyRef, blocksize) = rsaKey.keyRef
        
        /* Condition validation */
        guard let key = keyRef, let data = da, data.count > 0 else {
            return nil
        }

        // Create digital signature
        var buffer = [UInt8](repeating: 0, count: blocksize)
        defer { bzero(&buffer, buffer.count) }
        
        let status = SecKeyRawSign(key, di.padding, data.bytes(), data.count, &buffer, &blocksize)
        if status != errSecSuccess {
            return nil
        }
        return Data(bytes: buffer, count: blocksize)
    }
    
    /// Remove current key from keystore.
    public func remove() {
        rsaKey.key.remove()
    }
}
