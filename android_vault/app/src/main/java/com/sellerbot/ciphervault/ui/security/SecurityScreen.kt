package com.sellerbot.ciphervault.ui.security

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.ErrorOutline
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Menu
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.sellerbot.ciphervault.R
import com.sellerbot.ciphervault.model.Vault
import com.sellerbot.ciphervault.security.SecurityAudit
import com.sellerbot.ciphervault.ui.theme.Gold
import com.sellerbot.ciphervault.ui.theme.WarnAmber

/**
 * Password-hygiene dashboard.
 *
 * Advisory by design: it surfaces what needs attention and links straight to
 * the offending entry, but it never blocks anything. A vault the user is
 * still migrating into is not a reason to refuse to open.
 */
@androidx.compose.material3.ExperimentalMaterial3Api
@Composable
fun SecurityScreen(
    vault: Vault,
    onOpenEntry: (String) -> Unit,
    onOpenMenu: () -> Unit,
) {
    val report = remember(vault.liveEntries) { SecurityAudit.audit(vault) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.nav_security)) },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.background,
                ),
                navigationIcon = {
                    IconButton(onClick = onOpenMenu) {
                        Icon(Icons.Filled.Menu, contentDescription = stringResource(R.string.nav_menu))
                    }
                },
            )
        },
    ) { padding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(horizontal = 16.dp)
                .padding(padding),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            item {
                ScoreCard(
                    report = report,
                    modifier = Modifier.padding(top = 8.dp),
                )
            }

            if (report.findings.isEmpty()) {
                item { AllClear(report.totalEntries) }
            } else {
                item {
                    SectionHeader(
                        stringResource(R.string.security_findings, report.findings.size),
                    )
                }
                items(report.findings, key = { "${it.kind}-${it.entryId}" }) { finding ->
                    FindingRow(finding) { onOpenEntry(finding.entryId) }
                }
            }

            item { Spacer(Modifier.height(72.dp)) }
        }
    }
}

@androidx.compose.material3.ExperimentalMaterial3Api
@Composable
fun ScoreCard(report: SecurityAudit.Report, modifier: Modifier = Modifier) {
    val scoreColor = when {
        report.score >= 80 -> Gold
        report.score >= 50 -> WarnAmber
        else -> MaterialTheme.colorScheme.error
    }

    Column(
        modifier = modifier
            .fillMaxWidth()
            .background(MaterialTheme.colorScheme.surface, RoundedCornerShape(16.dp))
            .border(1.dp, MaterialTheme.colorScheme.outlineVariant, RoundedCornerShape(16.dp))
            .padding(18.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(
                imageVector = Icons.Filled.Shield,
                contentDescription = null,
                tint = scoreColor,
                modifier = Modifier.size(22.dp),
            )
            Spacer(Modifier.width(10.dp))
            Text(
                text = stringResource(R.string.security_score_title),
                style = MaterialTheme.typography.titleMedium,
            )
        }

        Spacer(Modifier.height(14.dp))

        Row(verticalAlignment = Alignment.Bottom) {
            Text(
                text = report.score.toString(),
                style = MaterialTheme.typography.displayLarge,
                color = scoreColor,
            )
            Text(
                text = "/100",
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(start = 4.dp, bottom = 10.dp),
            )
        }

        Spacer(Modifier.height(10.dp))

        LinearProgressIndicator(
            progress = { report.score / 100f },
            color = scoreColor,
            trackColor = MaterialTheme.colorScheme.surfaceVariant,
            modifier = Modifier
                .fillMaxWidth()
                .height(6.dp),
        )

        Spacer(Modifier.height(14.dp))

        Row(horizontalArrangement = Arrangement.spacedBy(16.dp)) {
            Stat(
                count = report.count(SecurityAudit.Kind.WEAK),
                label = stringResource(R.string.security_weak),
            )
            Stat(
                count = report.count(SecurityAudit.Kind.REUSED),
                label = stringResource(R.string.security_reused),
            )
            Stat(
                count = report.count(SecurityAudit.Kind.STALE),
                label = stringResource(R.string.security_stale),
            )
            Stat(
                count = report.count(SecurityAudit.Kind.NO_2FA),
                label = stringResource(R.string.security_no_2fa),
            )
        }
    }
}

@androidx.compose.material3.ExperimentalMaterial3Api
@Composable
fun Stat(count: Int, label: String) {
    Column {
        Text(
            text = count.toString(),
            style = MaterialTheme.typography.titleLarge,
            color = if (count == 0) {
                MaterialTheme.colorScheme.onSurfaceVariant
            } else {
                MaterialTheme.colorScheme.onSurface
            },
        )
        Text(
            text = label,
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@androidx.compose.material3.ExperimentalMaterial3Api
@Composable
fun FindingRow(finding: SecurityAudit.Finding, onClick: () -> Unit) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier
            .fillMaxWidth()
            .background(MaterialTheme.colorScheme.surface, RoundedCornerShape(12.dp))
            .border(1.dp, MaterialTheme.colorScheme.outlineVariant, RoundedCornerShape(12.dp))
            .clickable(onClick = onClick)
            .padding(12.dp),
    ) {
        Icon(
            imageVector = finding.kind.icon(),
            contentDescription = null,
            tint = finding.severity.color(),
            modifier = Modifier.size(20.dp),
        )

        Spacer(Modifier.width(12.dp))

        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = finding.entry.title,
                style = MaterialTheme.typography.titleSmall,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Text(
                text = finding.detail,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
            )
        }

        Text(
            text = finding.severity.label(),
            style = MaterialTheme.typography.labelSmall,
            color = finding.severity.color(),
        )
    }
}

@Composable
fun SecurityAudit.Severity.label(): String = when (this) {
    SecurityAudit.Severity.HIGH -> stringResource(R.string.security_high)
    SecurityAudit.Severity.MEDIUM -> stringResource(R.string.security_medium)
    SecurityAudit.Severity.LOW -> stringResource(R.string.security_low)
}

@Composable
fun SecurityAudit.Severity.color(): Color = when (this) {
    SecurityAudit.Severity.HIGH -> MaterialTheme.colorScheme.error
    SecurityAudit.Severity.MEDIUM -> WarnAmber
    SecurityAudit.Severity.LOW -> Gold
}

fun SecurityAudit.Kind.icon(): ImageVector = when (this) {
    SecurityAudit.Kind.WEAK -> Icons.Filled.Warning
    SecurityAudit.Kind.REUSED -> Icons.Filled.ErrorOutline
    SecurityAudit.Kind.STALE -> Icons.Filled.Info
    SecurityAudit.Kind.NO_2FA -> Icons.Filled.Shield
}

@androidx.compose.material3.ExperimentalMaterial3Api
@Composable
fun SectionHeader(text: String) {
    Text(
        text = text,
        style = MaterialTheme.typography.labelMedium,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = Modifier.padding(top = 8.dp, bottom = 2.dp),
    )
}

@androidx.compose.material3.ExperimentalMaterial3Api
@Composable
fun AllClear(entryCount: Int) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(top = 48.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Icon(
            imageVector = Icons.Filled.CheckCircle,
            contentDescription = null,
            tint = Gold,
            modifier = Modifier.size(48.dp),
        )
        Spacer(Modifier.height(12.dp))
        Text(
            text = stringResource(R.string.security_all_clear),
            style = MaterialTheme.typography.titleLarge,
            textAlign = TextAlign.Center,
        )
        Spacer(Modifier.height(4.dp))
        Text(
            text = stringResource(R.string.security_all_clear_body, entryCount),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center,
        )
    }
}