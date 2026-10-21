package io.github.cysin.sslsockspro.ui

import android.content.res.ColorStateList
import android.graphics.Typeface
import android.text.Editable
import android.text.InputType
import android.text.TextWatcher
import android.text.method.PasswordTransformationMethod
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.view.inputmethod.EditorInfo
import android.widget.EditText
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.viewinterop.AndroidView

/** Text input for anything that identifies the user or their servers.
 * Compose text fields cannot ask the keyboard to stop learning, so this uses
 * a platform field with no personalized learning or suggestions, no autofill
 * capture, and no copy of its text in saved instance state. The caller keeps
 * the value in memory (a ViewModel), never in a saved-state bundle. */
@Composable
internal fun SecureTextField(
    value: String,
    onValueChange: (String) -> Unit,
    label: String,
    modifier: Modifier = Modifier,
    secret: Boolean = false,
    singleLine: Boolean = true,
    monospace: Boolean = false,
    number: Boolean = false,
    lines: Int = 1,
    supportingText: String? = null,
    error: String? = null,
) {
    val latest by rememberUpdatedState(onValueChange)
    val colors = MaterialTheme.colorScheme
    val textColor = colors.onSurface.toArgb()
    val hintColor = colors.onSurfaceVariant.toArgb()
    val accent = colors.primary.toArgb()
    Column(modifier) {
        Text(label, style = MaterialTheme.typography.labelMedium, color = colors.onSurfaceVariant)
        AndroidView(modifier = Modifier.fillMaxWidth(), factory = { context ->
            EditText(context).apply {
                isSaveEnabled = false
                importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
                // The hint labels the field for accessibility services.
                hint = label
                imeOptions = EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING or
                    (if (singleLine) EditorInfo.IME_ACTION_DONE else EditorInfo.IME_ACTION_NONE)
                inputType = when {
                    number -> InputType.TYPE_CLASS_NUMBER
                    secret -> InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
                    singleLine -> InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS or InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD
                    else -> InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
                }
                if (secret) transformationMethod = PasswordTransformationMethod.getInstance()
                isSingleLine = singleLine
                if (!singleLine) {
                    minLines = lines; maxLines = maxOf(lines, 12)
                    gravity = Gravity.TOP or Gravity.START
                    isVerticalScrollBarEnabled = true
                }
                if (monospace) { typeface = Typeface.MONOSPACE; setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f) }
                setText(value)
                addTextChangedListener(object : TextWatcher {
                    override fun beforeTextChanged(text: CharSequence?, start: Int, count: Int, after: Int) = Unit
                    override fun onTextChanged(text: CharSequence?, start: Int, before: Int, count: Int) = Unit
                    override fun afterTextChanged(text: Editable?) { latest(text?.toString().orEmpty()) }
                })
            }
        }, update = { field ->
            if (field.text.toString() != value) {
                val cursor = field.selectionEnd
                field.setText(value)
                field.setSelection(cursor.coerceIn(0, value.length))
            }
            field.setTextColor(textColor)
            field.setHintTextColor(hintColor)
            field.backgroundTintList = ColorStateList.valueOf(accent)
        })
        (error ?: supportingText)?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = if (error != null) colors.error else colors.onSurfaceVariant) }
    }
}
