package Apps.yj.c2c

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import Apps.yj.c2c.ui.theme.C2cTheme
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.nfc.NdefMessage
import android.nfc.NdefRecord
import android.nfc.NfcAdapter
import android.util.Log
import android.widget.Toast
import androidx.compose.foundation.layout.Column
import androidx.compose.material3.Button
import arrow.core.Either
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.experimental.and

class MainActivity : ComponentActivity() {
    val broadcaster = UdpBroadcaster(this)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            C2cTheme {
                // A surface container using the 'background' color from the theme
                Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
                    Column {
                        SendButton(broadcaster)
                    }
                }
            }
        }
    }
    override fun onResume() {
        super.onResume()
        val nfcAdapter = NfcAdapter.getDefaultAdapter(this)
        val pendingIntent = PendingIntent.getActivity(
            this, 0,
            Intent(this, javaClass).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE
        )
        val intentFilters = arrayOf<IntentFilter>()
        val techLists = arrayOf<Array<String>>()
        nfcAdapter?.enableForegroundDispatch(this, pendingIntent, intentFilters, techLists)
        if(NfcAdapter.ACTION_NDEF_DISCOVERED == intent.action) {
            when (val result = parseNdefData(intent)) {
                is Either.Left -> {
                    Toast.makeText(this, result.value, Toast.LENGTH_SHORT).show()
                }
                is Either.Right -> {
                    val (port,pairCode) = result.value;
                    broadcaster.sendBroadcast(aesEncrypt(port.toString(),pairCode))
                }
            }

        }
    }

    override fun onPause() {
        super.onPause()
        val nfcAdapter = NfcAdapter.getDefaultAdapter(this)
        nfcAdapter?.disableForegroundDispatch(this)
    }
}

fun aesEncrypt(data: String, pwd: String): ByteArray {
    val digest = MessageDigest.getInstance("SHA-256")
    val bytes = digest.digest(pwd.toByteArray())
    val key = SecretKeySpec(bytes.copyOf(16), "AES")

    // Generate a random IV
    val ivSize = 16
    val iv = ByteArray(ivSize)
    SecureRandom().nextBytes(iv)
    val ivParameterSpec = IvParameterSpec(iv)

    // Initialize the cipher with the IV
    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    cipher.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec)

    // Encrypt the data
    val encryptedBytes = cipher.doFinal(data.toByteArray())

    // Combine the IV and the encrypted data
    return iv + encryptedBytes
}

fun parseNdefData(intent: Intent): Either<String,Pair<Short,String>> {
    val rawMsgs = intent.getParcelableArrayExtra(NfcAdapter.EXTRA_NDEF_MESSAGES,
        //   NdefMessage::class.java
    )?.map { it as NdefMessage }
    if(rawMsgs!=null) {
        val msg = rawMsgs[0];
        for (record in msg.records) {
            if (record.tnf == NdefRecord.TNF_WELL_KNOWN && record.type.contentEquals(NdefRecord.RTD_TEXT)) {
                val payload = record.payload
                val languageCodeLength = payload[0] and 0x3F
                val text = String(payload, languageCodeLength + 1, payload.size - languageCodeLength - 1, Charsets.UTF_8)
                val splitted = text.split("|")
                if(splitted.size>=2) {
                    return try {
                        val port = splitted[0].toShort()
                        val pairCode = splitted.subList(1,splitted.size).joinToString(separator = "|") {
                            it
                        }
                        Either.Right(Pair(port, pairCode))
                    } catch (e: NumberFormatException) {
                        Either.Left("Invalid data format: $text")
                    }
                }
                Log.d("YJ", "Text Record: $text")
            } else {
                Log.d("YJ", "Non-Text Record: ${record.toString()}")
            }
        }
    }
    return Either.Left("Cannot read data from this tag")
}

@Composable
fun SendButton(broadcaster: UdpBroadcaster) {
    Button(onClick = {
        broadcaster.sendBroadcast("Hello".toByteArray())
    }) { Text(text = "Send") }
}

@Composable
fun WriteTag(context: Context) {
    Button(onClick = {
        val msg = NdefMessage(
            NdefRecord.createTextRecord("text","5555|pwd"),
            NdefRecord.createApplicationRecord("Apps.yj.c2c")
        )
        //val nfcAdapter = NfcAdapter.getDefaultAdapter(context)
        //nfcAdapter.enableForegroundDispatch(this,)
        //val ndef = Ndef.get()
    }) {
        Text("Write")
    }
}

class UdpBroadcaster(private val context: Context) {
    companion object {
        private const val PORT = 8888
        private const val BROADCAST_IP = "255.255.255.255"
        private const val TIMEOUT = 5000 // 5秒超时
    }

    // 发送广播
    fun sendBroadcast(message: ByteArray) {
        CoroutineScope(Dispatchers.IO).launch {
            try {
                DatagramSocket().use { socket ->
                    socket.broadcast = true
                    socket.soTimeout = TIMEOUT

                    val sendData = message
                    val broadcastAddr = InetAddress.getByName(BROADCAST_IP)
                    val sendPacket = DatagramPacket(
                        sendData,
                        sendData.size,
                        broadcastAddr,
                        PORT
                    )

                    socket.send(sendPacket)
                }
            } catch (e: Exception) {
                e.printStackTrace()
            }
        }
    }


    // 带回调的发送方法
    fun sendBroadcastWithCallback(
        message: String,
        onSuccess: () -> Unit,
        onError: (String) -> Unit
    ) {
        CoroutineScope(Dispatchers.IO).launch {
            try {
               // if (!isNetworkAvailable()) {
               //     withContext(Dispatchers.Main) {
               //         onError("Network not available")
               //     }
               //     return@launch
               // }

                DatagramSocket().use { socket ->
                    socket.broadcast = true
                    socket.soTimeout = TIMEOUT

                    val sendData = message.toByteArray()
                    val broadcastAddr = InetAddress.getByName(BROADCAST_IP)
                    val sendPacket = DatagramPacket(
                        sendData,
                        sendData.size,
                        broadcastAddr,
                        PORT
                    )

                    socket.send(sendPacket)

                    withContext(Dispatchers.Main) {
                        onSuccess()
                    }
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    onError(e.message ?: "Unknown error")
                }
            }
        }
    }

}
