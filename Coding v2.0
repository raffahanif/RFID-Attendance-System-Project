#include <SPI.h>
#include <MFRC522.h>

const uint8_t RST_PIN = D3;
const uint8_t SS_PIN = D4;

MFRC522 mfrc522(SS_PIN, RST_PIN);
MFRC522::MIFARE_Key key;

int blockNum = 4;
byte bufferLen = 18;
byte readBlockData[18];
MFRC522::StatusCode status;

void setup() 
{
  Serial.begin(9600);
  SPI.begin();
  mfrc522.PCD_Init();
  Serial.println("Scan Kartu");
}

void loop()
{
  for (byte i = 0; i < 6; i++) {
    key.keyByte[i] = 0xFF;
  }

  if (!mfrc522.PICC_IsNewCardPresent()) return;
  if (!mfrc522.PICC_ReadCardSerial()) return;

  Serial.println("\n**Kartu Terdeteksi**");
  Serial.print("UID Kartu:");
  for (byte i = 0; i < mfrc522.uid.size; i++) {
    Serial.print(mfrc522.uid.uidByte[i] < 0x10 ? " 0" : " ");
    Serial.print(mfrc522.uid.uidByte[i], HEX);
  }
  Serial.print("\n");

  inputDataDanTulisKeBlok(4, "Nama Mahasiswa:, (akhiri dengan #)");
  inputDataDanTulisKeBlok(5, "NIM Mahasiswa:, (akhiri dengan #)");
  inputDataDanTulisKeBlok(6, "Jurusan Mahasiswa:, (akhiri dengan #)");
  inputDataDanTulisKeBlok(8, "Program Studi Mahasiswa:, (akhiri dengan #)");

  mfrc522.PICC_HaltA();
  mfrc522.PCD_StopCrypto1();
}

void inputDataDanTulisKeBlok(int blockNumber, const char* prompt) {
  Serial.println(F("---------------------------------------"));
  Serial.println(prompt);
  byte buffer[18];
  byte len = Serial.readBytesUntil('#', (char *) buffer, 16);
  for (byte i = len; i < 16; i++) buffer[i] = ' ';
  WriteDataToBlock(blockNumber, buffer);
  ReadDataFromBlock(blockNumber, readBlockData);
  dumpSerial(blockNumber, readBlockData);
}

void WriteDataToBlock(int blockNum, byte blockData[]) 
{
  status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, blockNum, &key, &(mfrc522.uid));
  if (status != MFRC522::STATUS_OK) {
    Serial.println("Kartu gagal terbaca");
    return;
  }

  status = mfrc522.MIFARE_Write(blockNum, blockData, 16);
  if (status != MFRC522::STATUS_OK) {
    Serial.println("Kartu gagal terbaca");
    return;
  }
}

void ReadDataFromBlock(int blockNum, byte readBlockData[]) 
{
  status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, blockNum, &key, &(mfrc522.uid));
  if (status != MFRC522::STATUS_OK) {
    Serial.println("Kartu gagal terbaca");
    return;
  }

  status = mfrc522.MIFARE_Read(blockNum, readBlockData, &bufferLen);
  if (status != MFRC522::STATUS_OK) {
    Serial.println("Kartu gagal terbaca");
    return;
  }
}

void dumpSerial(int blockNum, byte blockData[]) 
{
  Serial.print("\nData yang disimpan pada blok ");
  Serial.print(blockNum);
  Serial.print(": ");
  for (int j = 0; j < 16; j++) {
    Serial.write(readBlockData[j]);
  }
  Serial.print("\n");

  // Kosongkan array readBlockData
  for (int i = 0; i < sizeof(readBlockData); ++i) {
    readBlockData[i] = (char)0;
  }
}
