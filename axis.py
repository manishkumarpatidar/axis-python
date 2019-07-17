def axis_request(request):
    data = {}
    data['vpc_Version'] = settings.VERSION
    data['vpc_AccessCode'] = settings.MERCHANT_ACCESS_CODE
    data['vpc_MerchantId'] = settings.MERCHANT_ID
    data['vpc_ReturnURL'] = settings.RETURN_URL
    data['vpc_Command'] = settings.VPC_COMMAND
    data['vpc_MerchTxnRef'] = Checksum.__id_generator__()
    data['vpc_OrderInfo'] = data['vpc_MerchTxnRef']
    data['vpc_Amount'] = 10000
    
    data = dict(sorted(data.items()))
    secure_secret = settings.SECURE_SECRET
    #presaving of data in payment table
    
    dataToPostToPG = ''
    for key, values in data.items():
        secure_secret = str(secure_secret)+str(values)
        dataToPostToPG += key+"="+str(values)+"::"
    #Remove lat ::
    dataToPostToPG = dataToPostToPG[:-2]
    secureHash = hashlib.sha256(secure_secret.encode('utf-8')).hexdigest()
    dataToPostToPG="vpc_SecureHash="+secureHash+"::"+dataToPostToPG
    aes = AESCipher(settings.ENC_KEY)
    ciphertext_base64 = aes.encrypt(dataToPostToPG)
    if ciphertext_base64:
        data_dict = {
                    'vpc_MerchantId':settings.MERCHANT_ID,
                    'EncData':ciphertext_base64
                }
        param_dict = data_dict
    return render(request,"axis_payment.html",{'axisdict':param_dict, 'axis_url':settings.GATEWAY_URL})


@csrf_exempt
def axis_response(request):
    if request.method == "POST":
        if request.POST.get('EncDataResp') != "":
            ciphertext_dec = ""
            ciphertext_base64 = request.POST.get('EncDataResp')
            #AES Decryption
            aes = AESCipher(settings.ENC_KEY)
            ciphertext_dec = aes.decrypt(ciphertext_base64)
            #removing last ::
            if ciphertext_dec.rfind('::') != -1:
                ciphertext_dec = ciphertext_dec[:-2]
            #Spliting str to list 
            array_data_string = ciphertext_dec.split("::")
            origial_array = {}
            if array_data_string:
                for value in array_data_string:
                    temp_array = value.split("||")
                    origial_array[temp_array[0]] = temp_array[1]
                    
            # Get the hash sent by PG 
            received_hash= origial_array["vpc_SecureHash"]
            del origial_array["vpc_SecureHash"]
            
            #Calculate hash of parameters received from PG
            origial_array = dict(sorted(origial_array.items()))
            
            if origial_array:
                secure_secret = settings.SECURE_SECRET
                for key, val in origial_array.items():
                    secure_secret = secure_secret+val
            Cal_hash = hashlib.sha256(secure_secret.encode('utf-8')).hexdigest()
            data_dict = {
                'vpc_Version':origial_array.get('vpc_Version',None),
                'vpc_Command':origial_array.get('vpc_Command',None),
                'ORDERID':origial_array.get('vpc_MerchTxnRef',None),
                'MID':origial_array.get('vpc_Merchant',None),
                'STATUS':'TXN_SUCCESS' if origial_array.get('vpc_TxnResponseCode',None)=='0' else 'TXN_FAILURE',
                'RESPCODE': origial_array.get('vpc_AcqResponseCode',None),
                'RESPMSG':origial_array.get('vpc_Message',None),
                'vpc_Locale':origial_array.get('vpc_Locale',None),
                'TXNAMOUNT':int(origial_array.get('vpc_Amount',None))/100,
                'vpc_ReceiptNo':origial_array.get('vpc_ReceiptNo',None),
                'vpc_Card':origial_array.get('vpc_Card',None),
                'TXNID':origial_array.get('vpc_TransactionNo',None),
                'vpc_BatchNo':origial_array.get('vpc_BatchNo',None),
                'vpc_AuthorizeId':origial_array.get('vpc_AuthorizeId',None),
                'vpc_VerSecurityLevel':origial_array.get('vpc_VerSecurityLevel',None),
                'vpc_3DSXID':origial_array.get('vpc_3DSXID',None),
                'vpc_3DSECI':origial_array.get('vpc_3DSECI',None),
                'vpc_VerToken':origial_array.get('vpc_VerToken',None),
                'vpc_3DSenrolled':origial_array.get('vpc_3DSenrolled',None),
                'vpc_3DSstatus':origial_array.get('vpc_3DSstatus',None),
                'vpc_VerStatus':origial_array.get('vpc_VerStatus',None),
                'vpc_VerType':origial_array.get('vpc_VerType',None),
                'CURRENCY':origial_array.get('vpc_Currency',None),
                'vpc_AcqCSCRespCode':origial_array.get('vpc_AcqCSCRespCode',None),
                'vpc_CSCResultCode':origial_array.get('vpc_CSCResultCode',None),
                }
            if Cal_hash==received_hash:
                return render(request,"axis_response.html",{"axis":data_dict})
            else:
                return HttpResponse("Hash verification failed. Please try again")
    return HttpResponse(status=200)