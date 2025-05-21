#Requires the following packages: 
#requests
#pycryptodome

import requests
import json
import base64
import time
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import hashlib
from datetime import datetime
from getpass import getpass

TOPIC = "8hr3h4ufoh384y3f0p4h3"
PRIVATE_KEY_PATH = "clave_privada.pem"

def getLastMessage(topic):
  resp = requests.get("https://ntfy.sh/" + topic + "/json?poll=1")
  newestMessage = None
  for line in resp.iter_lines():
    if line:
      jLine = json.loads(line)
      if newestMessage is None:
        newestMessage = jLine
      else:
        if jLine["time"] > newestMessage["time"]:
          newestMessage = jLine
  if newestMessage is None:
    return ""
  return newestMessage


def validateQueryFormat(input):
  if input.startswith("QUERY:") is False:
    return False
  try:
    base64.b64decode(input.split(":")[1], validate=True)
  except Exception:
    return False
  return True


def decipherMessage(message, keyPath):
  try:
    key = RSA.importKey(open(keyPath).read())
    cipher = PKCS1_OAEP.new(key)
    clearMessage = cipher.decrypt(base64.b64decode(message))
    return clearMessage.decode("utf-8")
  except Exception as e:
    raise ValueError(f"Error: {e}")


def requestAndEncodePass(publicEphemeralKey):
  sha256_hash = hashlib.sha256()
  time.sleep(3)
  password = getpass()
  sha256_hash.update(password.encode('utf-8'))
  checksum = sha256_hash.hexdigest()
  messageToSecure = "PASS:" + password + ":CHECKSUM:" + checksum
  key = RSA.importKey(publicEphemeralKey)
  cipher = PKCS1_OAEP.new(key)
  ciphertext = cipher.encrypt(messageToSecure.encode('utf-8'))
  ciphertextEncoded = base64.b64encode(ciphertext)
  return ciphertextEncoded


def sendResponse(messagetoSend, topic):
  try:
    messagetoSend = "RESPONSE:" + messagetoSend.decode('utf-8')
    requests.post("https://ntfy.sh/" + topic,
                  data=messagetoSend.encode(encoding='utf-8'))
    print("Response sent")
  except Exception as e:
    raise ValueError(f"Error: {e}")


def processMessage(message, time, topic, cache=False):
  if validateQueryFormat(message):
    if cache:
      print("In cache...")
    print("Request time: " +
          datetime.fromtimestamp(time).strftime('%Y-%m-%d %H:%M:%S'))
    decipherLastMessage = decipherMessage(message.split(":")[1], PRIVATE_KEY_PATH)
    cipherResponse = requestAndEncodePass(decipherLastMessage)
    sendResponse(cipherResponse, topic)
  else:
    raise ValueError("Invalid message")


def initSream(topic):
  resp = requests.get("https://ntfy.sh/" + topic + "/json", stream=True)
  for line in resp.iter_lines():
    try:
      if line:
        jLine = json.loads(line)
        if jLine["event"] == "message":
          if jLine["message"] == "OK":
            print("Pass Accepted :)")
          elif jLine["message"].startswith(
              "RESPONSE") or jLine["message"] == "NEED PASS":
            continue
          else:
            processMessage(jLine["message"], jLine["time"], topic)
            print("Waiting for response...")
    except Exception as e:
      print(f"{e}")
      pass


try:
  lastMessage = getLastMessage(TOPIC)
  print()
  if lastMessage != "":
    processMessage(lastMessage["message"],
                   lastMessage["time"],
                   TOPIC,
                   cache=True)
    print("Starting stream, waiting for response...")
  else:
    raise ValueError("Last message does not exist")
except Exception as e:
  print(f"{e}, Starting stream...")
  pass

initSream(TOPIC)
