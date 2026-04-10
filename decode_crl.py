from asn1c_lib import decode_oer
import json, sys                                                                                                   
                                                                                                                   
data = open('/tmp/iss_crl.coer','rb').read()                                                                       
try:
      outer = decode_oer('Ieee1609Dot2Data', data)                                                                   
      signed = outer['content']['signedData']                                                                      
      payload_hex = signed['tbsData']['payload']['data']['content']['unsecuredData']
      crl_bytes = bytes.fromhex(payload_hex)                                                                         
except Exception as e:
      print(f'outer decode: {e}', file=sys.stderr)                                                                   
      crl_bytes = data                                                                                             
                                                                                                                     
crl = decode_oer('CrlContents', crl_bytes)
print(json.dumps(crl, indent=2, default=str))  
