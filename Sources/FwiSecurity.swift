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


/// DER class supported.
public enum FwiDERClass: UInt8 {
    case universal        = 0x00
    case application      = 0x40
    case contextSpecific  = 0x80
    
    public func identifier(value: FwiDERValue, additionalValue v: UInt8 = 0) -> UInt8 {
        return (self.rawValue | v | value.rawValue)
    }
    
    public var description: String {
        switch self {
        case .universal:
            return "U"
            
        case .application:
            return "A"
            
        case .contextSpecific:
            return "C"
        }
    }
}

/// DER length supported.
public enum FwiDERLength: UInt8 {
    case level1           = 0x81
    case level2           = 0x82
    case level3           = 0x83
    case level4           = 0x84
}

/// DER value supported.
public enum FwiDERValue: UInt8 {
    case none             = 0x00
    
    case boolean          = 0x01    // Primitive
    case integer          = 0x02    // Primitive
    case bitString        = 0x03    // Primitive
    case octetString      = 0x04    // Primitive
    case null             = 0x05    // Primitive
    case objectIdentifier = 0x06    // Primitive
    case enumerated       = 0x0a    // Primitive
    case utf8String       = 0x0c    // Primitive
    case numericString    = 0x12    // Primitive
    case printableString  = 0x13    // Primitive
    case t61String        = 0x14    // Primitive
//	case videotexString   = 0x15    // Primitive    // Not supported
    case ia5String        = 0x16    // Primitive
    case utcTime          = 0x17    // Primitive
    case generalizedTime  = 0x18    // Primitive
    case graphicString    = 0x19    // Primitive
    case visibleString    = 0x1a    // Primitive
    case generalString    = 0x1b    // Primitive
    case universalString  = 0x1c    // Primitive
    case bmpString        = 0x1e    // Primitive
    
    case sequence         = 0x10    // Constructed
    case set              = 0x11    // Constructed
    
    public var description: String {
        switch self {
        case .boolean:
            return "Boolean"
            
        case .integer:
            return "Integer"
            
        case .bitString:
            return "Bit-String"
            
        case .octetString:
            return "Octet-String"
            
        case .null:
            return "Null"
            
        case .objectIdentifier:
            return "Object-Identifier"
            
        case .enumerated:
            return "Enumerated"
            
        case .utf8String:
            return "UTF8-String"
            
        case .numericString:
            return "Numeric-String"
            
        case .printableString:
            return "Printable-String"
            
        case .t61String:
            return "T61-String"
            
//        case .videotexString:
//            return "Videotex-String"
            
        case .ia5String:
            return "IA5-String"
            
        case .utcTime:
            return "UTC-Time"
            
        case .generalizedTime:
            return "GMT-Time"
            
        case .graphicString:
            return "Graphic-String"
            
        case .visibleString:
            return "Visible-String"
            
        case .generalString:
            return "General-String"
            
        case .universalString:
            return "Universal-String"
            
        case .bmpString:
            return "BMP-String"
            
        case .sequence:
            return "Sequence"
            
        case .set:
            return "Set"
            
        default:
            return ""
        }
    }
}

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
    
    public var padding: SecPadding {
        switch self {
        case .sha256:
            return SecPadding.PKCS1SHA256
            
        case .sha384:
            return SecPadding.PKCS1SHA384
            
        case .sha512:
            return SecPadding.PKCS1SHA512
            
        default:
            return SecPadding.PKCS1SHA1
        }
    }
    
    public var length: Int {
        switch self {
        case .sha256:
            return Int(CC_SHA256_DIGEST_LENGTH)
            
        case .sha384:
            return Int(CC_SHA384_DIGEST_LENGTH)
            
        case .sha512:
            return Int(CC_SHA512_DIGEST_LENGTH)
            
        default:
            return Int(CC_SHA1_DIGEST_LENGTH)
        }
    }
    
    public var digestOID: String {
        switch self {
        case .sha256:
            return "2.16.840.1.101.3.4.2.1"
            
        case .sha384:
            return "2.16.840.1.101.3.4.2.2"
            
        case .sha512:
            return "2.16.840.1.101.3.4.2.3"
            
        default:
            return "1.3.14.3.2.26"
        }
    }
    
    public var signatureOID: String {
        switch self {
        case .sha256:
            return "1.2.840.113549.1.1.11"
            
        case .sha384:
            return "1.2.840.113549.1.1.12"
            
        case .sha512:
            return "1.2.840.113549.1.1.13"
            
        default:
            return "1.2.840.113549.1.1.5"
        }
    }
    
    public func sha(withData d: Data?) -> Data? {
        guard let bytes = d?.bytes(), bytes.count > 0 else {
            return nil
        }

        var hashBytes = [UInt8](repeating: 0, count: length)
        switch self {
        case .sha256:
            CC_SHA256(bytes, CC_LONG(length), &hashBytes)
            
        case .sha384:
            CC_SHA384(bytes, CC_LONG(length), &hashBytes)
            
        case .sha512:
            CC_SHA512(bytes, CC_LONG(length), &hashBytes)
            
        default:
            CC_SHA1(bytes, CC_LONG(length), &hashBytes)
        }
        return Data(bytesNoCopy: &hashBytes, count: length, deallocator: .none)
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
    
    case asen
    case extr
    case modi
    case next
    case priv
    case sens
    case snrc
    case vyrc
    
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
        
        case .asen: return "asen"
        case .extr: return "extr"
        case .modi: return "modi"
        case .next: return "next"
        case .priv: return "priv"
        case .sens: return "sens"
        case .snrc: return "snrc"
        case .vyrc: return "vyrc"
        }
    }
}

/// Parse DER's class from identifier.
///
/// - parameter identifier (required): DER's identifier
internal func FwiGetDerClass(_ identifier: UInt8) -> FwiDERClass {
    return FwiDERClass(rawValue: identifier & 0xc0) ?? .universal
}

/// Parse DER's value from identifier.
///
/// - parameter identifier (required): DER's identifier
internal func FwiGetDerValue(_ identifier: UInt8) -> FwiDERValue {
    return FwiDERValue(rawValue: identifier & 0x1f) ?? .none
}

//FwiDigest (^FwiDigestWithDigestOID)(NSString *digestOID) = ^(NSString *digestOID) {
//    if ([digestOID isEqualToString:@"2.16.840.1.101.3.4.2.1"]) return kSHA256;
//    else if ([digestOID isEqualToString:@"2.16.840.1.101.3.4.2.2"]) return kSHA384;
//    else if ([digestOID isEqualToString:@"2.16.840.1.101.3.4.2.3"]) return kSHA512;
//    else return kSHA1;
//};
//FwiDigest (^FwiDigestWithSignatureOID)(NSString *signatureOID) = ^(NSString *signatureOID) {
//    if ([signatureOID isEqualToString:@"1.2.840.113549.1.1.11"]) return kSHA256;
//    else if ([signatureOID isEqualToString:@"1.2.840.113549.1.1.12"]) return kSHA384;
//    else if ([signatureOID isEqualToString:@"1.2.840.113549.1.1.13"]) return kSHA512;
//    else return kSHA1;
//};
