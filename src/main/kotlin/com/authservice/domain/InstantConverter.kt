package com.authservice.domain

import jakarta.persistence.AttributeConverter
import jakarta.persistence.Converter
import java.time.Instant

/**
 * Store Instant fields as ISO-8601 TEXT in SQLite.
 *
 * Hibernate 6 maps Instant to JDBC Timestamp (epoch millis) by default, but the SQLite JDBC
 * driver's getTimestamp() expects a formatted datetime string — not a raw Long — and throws
 * "Error parsing time stamp" when it gets one. Storing as ISO-8601 TEXT avoids the mismatch
 * and is human-readable in the DB file. autoApply = true covers all Instant fields globally.
 */
@Converter(autoApply = true)
class InstantConverter : AttributeConverter<Instant, String> {
    override fun convertToDatabaseColumn(instant: Instant?): String? = instant?.toString()
    override fun convertToEntityAttribute(dbData: String?): Instant? = dbData?.let { Instant.parse(it) }
}
