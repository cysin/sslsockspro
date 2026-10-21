package io.github.cysin.sslsockspro

import android.os.Bundle
import android.view.accessibility.AccessibilityNodeInfo
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.cysin.sslsockspro.ui.MainActivity
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class UiDeviceTest {
    @get:Rule val ui = createAndroidComposeRule<MainActivity>()

    private fun tab(name: String) = ui.onNodeWithContentDescription(name, useUnmergedTree = true).performClick()

    /** Secure fields are platform EditTexts outside the Compose semantics
     * tree; reach them through accessibility by their hint. */
    private fun field(hint: String): AccessibilityNodeInfo {
        val automation = InstrumentationRegistry.getInstrumentation().uiAutomation
        fun find(node: AccessibilityNodeInfo?): AccessibilityNodeInfo? {
            if (node == null) return null
            if (node.isEditable && node.hintText?.toString() == hint) return node
            for (index in 0 until node.childCount) find(node.getChild(index))?.let { return it }
            return null
        }
        var found: AccessibilityNodeInfo? = null
        ui.waitUntil(10000) { found = find(automation.rootInActiveWindow); found != null }
        return found!!
    }
    private fun enter(hint: String, text: String) {
        assertTrue(field(hint).performAction(AccessibilityNodeInfo.ACTION_SET_TEXT,
            Bundle().apply { putCharSequence(AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE, text) }))
        ui.waitForIdle()
    }
    private fun text(hint: String): String = field(hint).also { it.refresh() }.text?.toString().orEmpty()

    @Test fun navigationThemeAndPrivateDraftSurviveRotation() {
        val store = (ui.activity.application as TunnelApplication).profiles
        val original = store.read()
        try {
            ui.waitUntil(10000) { ui.onAllNodesWithText("Your connection").fetchSemanticsNodes().isNotEmpty() }
            tab("Profiles")
            ui.onNodeWithContentDescription("Create profile").assertExists()
            tab("Certificates")
            ui.onNodeWithText("Certificates stay in encrypted private app storage. Private keys are never displayed here.").assertExists()
            tab("Logs")
            ui.onNodeWithText("Connection log").assertExists()
            tab("Settings")
            ui.onNodeWithText("Dark").performClick()
            ui.waitUntil(10000) { store.read().settings.darkTheme == true }
            ui.activityRule.scenario.recreate()
            ui.onNodeWithText("Appearance").assertExists()
            ui.onNodeWithText("Dark").assertIsSelected()

            tab("Profiles")
            ui.onNodeWithContentDescription("Create profile").performClick()
            enter("Profile name", "Private rotation draft")
            enter("Server IP or hostname", "203.0.113.7")
            ui.activityRule.scenario.recreate()
            assertEquals("Private rotation draft", text("Profile name"))
            assertEquals("203.0.113.7", text("Server IP or hostname"))
            ui.onNodeWithContentDescription("Cancel editing").performClick()
            assertEquals(original.profiles, store.read().profiles)

            tab("Settings")
            if (original.profiles.isNotEmpty()) {
                ui.onNodeWithText("Create encrypted local backup").performClick()
                enter("Backup password", "temporary-test-password")
                ui.activityRule.scenario.recreate()
                ui.onNodeWithText("Encrypt backup").assertExists()
                ui.onNodeWithText("Encrypt and save").assertIsEnabled()
                ui.onNodeWithText("Cancel").performClick()
            }
            tab("Connection")
            ui.onNodeWithText("Your connection").assertExists()
        } finally { store.write(original) }
    }
}
