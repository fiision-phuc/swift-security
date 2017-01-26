//  Project name: FwiSecurity
//  File name   : FwiSecurity.swift
//
//  Author      : Phuc, Tran Huu
//  Created date: 12/6/16
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


/// AES key size supported.
public enum FwiAESSize {
    case size128            // 16 bytes
    case size192            // 24 bytes
    case size256            // 32 bytes
    
    public var length: Int {
        switch self {
        case .size192:
            return kCCKeySizeAES192
            
        case .size256:
            return kCCKeySizeAES256
            
        default:
            return kCCKeySizeAES128
        }
    }
}

/// RSA key size supported.
public enum FwiRSASize: Int {
    case size1024 = 1024    // 128 bytes
    case size2048 = 2048    // 256 bytes
    case size4096 = 4096    // 512 bytes
}

/// RSA digest size supported.
public enum FwiDigest {
    case sha1               // 20 bytes
    case sha256             // 32 bytes
    case sha384             // 48 bytes
    case sha512             // 64 bytes
    
    public var algorithm: CCHmacAlgorithm {
        switch self {
        case .sha256:
            return CCHmacAlgorithm(kCCHmacAlgSHA256)
            
        case .sha384:
            return CCHmacAlgorithm(kCCHmacAlgSHA384)
            
        case .sha512:
            return CCHmacAlgorithm(kCCHmacAlgSHA512)
            
        default:
            return CCHmacAlgorithm(kCCHmacAlgSHA1)
        }
    }
    
    public var length: Int32 {
        switch self {
        case .sha256:
            return CC_SHA256_DIGEST_LENGTH
            
        case .sha384:
            return CC_SHA384_DIGEST_LENGTH
            
        case .sha512:
            return CC_SHA512_DIGEST_LENGTH
            
        default:
            return CC_SHA1_DIGEST_LENGTH
        }
    }
    
}

/// Keychain's attributes.
internal enum SecAttr {
    case pdmn
    case agrp
    case cdat
    case mdat
    case desc
    case icmt
    case crtr
    case type
    case labl
    case invi
    case nega
    case acct
    case svce
    case gena
    case sdmn
    case srvr
    case ptcl
    case atyp
    case port
    case path
    case ctyp
    case cenc
    case subj
    case issr
    case slnr
    case skid
    case pkhh
    case kcls
    case klbl
    case perm
    case atag
    case bsiz
    case esiz
    case encr
    case decr
    case drve
    case sign
    case vrfy
    case wrap
    case unwp
    
    var value: String {
        switch self {
        case .pdmn: return "\(kSecAttrAccessible)"
        case .agrp: return "\(kSecAttrAccessGroup)"
        case .cdat: return "\(kSecAttrCreationDate)"
        case .mdat: return "\(kSecAttrModificationDate)"
        case .desc: return "\(kSecAttrDescription)"
        case .icmt: return "\(kSecAttrComment)"
        case .crtr: return "\(kSecAttrCreator)"
        case .type: return "\(kSecAttrType)"
        case .labl: return "\(kSecAttrLabel)"
        case .invi: return "\(kSecAttrIsInvisible)"
        case .nega: return "\(kSecAttrIsNegative)"
        case .acct: return "\(kSecAttrAccount)"
        case .svce: return "\(kSecAttrService)"
        case .gena: return "\(kSecAttrGeneric)"
        case .sdmn: return "\(kSecAttrSecurityDomain)"
        case .srvr: return "\(kSecAttrServer)"
        case .ptcl: return "\(kSecAttrProtocol)"
        case .atyp: return "\(kSecAttrAuthenticationType)"
        case .port: return "\(kSecAttrPort)"
        case .path: return "\(kSecAttrPath)"
        case .ctyp: return "\(kSecAttrCertificateType)"
        case .cenc: return "\(kSecAttrCertificateEncoding)"
        case .subj: return "\(kSecAttrSubject)"
        case .issr: return "\(kSecAttrIssuer)"
        case .slnr: return "\(kSecAttrSerialNumber)"
        case .skid: return "\(kSecAttrSubjectKeyID)"
        case .pkhh: return "\(kSecAttrPublicKeyHash)"
        case .kcls: return "\(kSecAttrKeyClass)"
        case .klbl: return "\(kSecAttrApplicationLabel)"
        case .perm: return "\(kSecAttrIsPermanent)"
        case .atag: return "\(kSecAttrApplicationTag)"
        case .bsiz: return "\(kSecAttrKeySizeInBits)"
        case .esiz: return "\(kSecAttrEffectiveKeySize)"
        case .encr: return "\(kSecAttrCanEncrypt)"
        case .decr: return "\(kSecAttrCanDecrypt)"
        case .drve: return "\(kSecAttrCanDerive)"
        case .sign: return "\(kSecAttrCanSign)"
        case .vrfy: return "\(kSecAttrCanVerify)"
        case .wrap: return "\(kSecAttrCanWrap)"
        case .unwp: return "\(kSecAttrCanUnwrap)"
        }
    }
}
