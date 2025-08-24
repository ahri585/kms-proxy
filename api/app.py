import os
from flask import Flask, jsonify
import boto3
from botocore.exceptions import ClientError

REGION = os.getenv("AWS_REGION", "ap-northeast-2")
KMS_KEY_ID = os.getenv("KMS_KEY_ID", "alias/KEK")


app = Flask(__name__)
kms = boto3.client("kms", region_name=REGION)


@app.get("/api/health")
def health():
    return "api ok\n", 200

@app.get("/api/kms-test")
def kms_test():
    try:
        res = kms.generate_data_key(KeyId=KMS_KEY_ID, KeySpec="AES_256")

        ct_len = len(res.get("CiphertextBlob", b"") or b"")
        return jsonify({"ok": True, "ciphertext_blob_len": ct_len}), 200
    except ClientError as e:
        return jsonify({"ok":False, "error": str(e)}), 500



if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
