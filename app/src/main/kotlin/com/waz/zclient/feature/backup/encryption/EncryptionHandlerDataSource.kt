package com.waz.zclient.feature.backup.encryption

import com.waz.model.UserId
import com.waz.zclient.core.exception.Failure
import com.waz.zclient.core.exception.IOFailure
import com.waz.zclient.core.functional.Either
import com.waz.zclient.core.functional.flatMap
import com.waz.zclient.core.functional.map
import com.waz.zclient.core.logging.Logger.Companion.verbose
import com.waz.zclient.feature.backup.encryption.crypto.Crypto
import com.waz.zclient.feature.backup.encryption.error.EncryptionFailure
import com.waz.zclient.feature.backup.encryption.header.EncyptionHeaderMetaData
import com.waz.zclient.feature.backup.encryption.header.TOTAL_HEADER_LENGTH
import java.io.File
import java.io.IOException

class EncryptionHandlerDataSource(
    private val crypto: Crypto,
    private val encryptedHeaderMetaData: EncyptionHeaderMetaData
) {

    fun encryptBackup(backupFile: File, userId: UserId, password: String): Either<Failure, File> =
        try {
            loadCryptoLibrary()
            val salt = crypto.generateSalt()
            encryptedMetaDataBytes(salt, userId).flatMap { meta ->
                val backupBytes = backupFile.readBytes()
                encryptWithHash(backupBytes, password, salt).map { encryptedBytes ->
                    return@map File(backupFile.parentFile, backupFile.name + "_encrypted").apply {
                        writeBytes(meta)
                        writeBytes(encryptedBytes)
                    }
                }
            }
        } catch (ex: IOException) {
            Either.Left(IOFailure(ex))
        }

    private fun encryptWithHash(msg: ByteArray, password: String, salt: ByteArray): Either<Failure, ByteArray> =
        hash(password, salt)?.let { key ->
            checkExpectedKeySize(key.size, crypto.encryptExpectedKeyBytes())
            encryptAndCipher(msg, key)
        } ?: Either.Left(EncryptionFailure("Failed to init encrypt"))

    private fun encryptAndCipher(msg: ByteArray, key: ByteArray): Either<Failure, ByteArray>? {
        val header = ByteArray(crypto.streamHeaderLength())
        return crypto.initEncryptState(key, header)?.let {
            val cipherText = ByteArray(msg.size + crypto.aBytesLength())
            val encrypted = msg + cipherText
            when (val ret: Int = crypto.generatePushMessagePart(it, cipherText, msg)) {
                0 -> Either.Right(encrypted)
                else -> Either.Left(EncryptionFailure("Failed to decrypt backup, got code $ret"))
            }
        }
    }
    
    //This method returns the metadata in the format described here:
    //https://github.com/wearezeta/documentation/blob/master/topics/backup/use-cases/001-export-history.md
    private fun encryptedMetaDataBytes(salt: ByteArray, userId: UserId): Either<Failure, ByteArray> =
        hash(userId.str(), salt)?.let { hash ->
            encryptedHeaderMetaData.writeEncryptedMetaData(salt, hash)
        } ?: Either.Left(EncryptionFailure("Failed to hash account id for backup"))

    fun decryptBackup(backupFile: File, userId: UserId, password: String): Either<Failure, File> {
        loadCryptoLibrary()
        return encryptedHeaderMetaData.readEncryptedMetadata(backupFile)?.let { metaData ->
            hash(userId.str(), metaData.salt)?.let {
                when (it.contentEquals(metaData.uuidHash)) {
                    true -> decryptBackupFile(password, backupFile, metaData.salt)
                    false -> Either.Left(EncryptionFailure("Uuid hashes don't match"))
                }
            } ?: Either.Left(EncryptionFailure("Uuid hashing failed"))
        } ?: Either.Left(EncryptionFailure("metadata could not be read"))
    }

    private fun decryptBackupFile(password: String, backupFile: File, salt: ByteArray): Either<Failure, File> {
        val encryptedBackupBytes = ByteArray(TOTAL_HEADER_LENGTH)
        backupFile.inputStream().buffered().read(encryptedBackupBytes)
        return decryptWithHash(encryptedBackupBytes, password, salt).map { decryptedBackupBytes ->
            File.createTempFile("wire_backup", ".zip").apply { writeBytes(decryptedBackupBytes) }
        }
    }

    private fun decryptWithHash(input: ByteArray, password: String, salt: ByteArray): Either<Failure, ByteArray> =
        hash(password, salt)?.let { key ->
            checkExpectedKeySize(key.size, crypto.decryptExpectedKeyBytes())
            decryptAndCipher(input, key)
        } ?: Either.Left(EncryptionFailure("Couldn't derive key from password"))

    private fun decryptAndCipher(input: ByteArray, key: ByteArray): Either<Failure, ByteArray>? {
        val header = input.take(crypto.streamHeaderLength()).toByteArray()
        return crypto.initDecryptState(key, header)?.let { state ->
            val cipherText = input.drop(crypto.streamHeaderLength()).toByteArray()
            val decrypted = ByteArray(cipherText.size + crypto.aBytesLength())
            when (val ret: Int = crypto.generateDecryptMessagePart(state, decrypted, cipherText)) {
                0 -> Either.Right(decrypted)
                else -> Either.Left(EncryptionFailure("Failed to decrypt backup, got code $ret"))
            }
        } ?: Either.Left(EncryptionFailure("Failed to init decrypt"))
    }

    private fun checkExpectedKeySize(size: Int, expectedKeySize: Int) =
        size.takeIf { it != expectedKeySize }?.let {
            verbose(TAG, "Key length invalid: $it did not match $expectedKeySize")
        }

    private fun loadCryptoLibrary() = crypto.loadLibrary

    private fun hash(input: String, salt: ByteArray): ByteArray? {
        val output = ByteArray(crypto.decryptExpectedKeyBytes())
        val passBytes = input.toByteArray()
        val ret = crypto.generatePwhashMessagePart(output, passBytes, salt)
        return ret.takeIf { it == 0 }?.let { output }
    }

    companion object {
        const val TAG = "EncryptionHandler"
    }
}
