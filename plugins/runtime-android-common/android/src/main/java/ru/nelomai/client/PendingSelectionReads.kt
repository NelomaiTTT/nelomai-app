package ru.nelomai.client

/** Small bounded callback collection which reports overflow instead of throwing. */
class PendingSelectionReads<T>(private val capacity: Int) {
    private val callbacks = ArrayDeque<(Result<T>) -> Unit>()

    init {
        require(capacity > 0)
    }

    @Synchronized
    fun offer(callback: (Result<T>) -> Unit): Boolean {
        if (callbacks.size >= capacity) return false
        callbacks.addLast(callback)
        return true
    }

    @Synchronized
    fun take(limit: Int): List<(Result<T>) -> Unit> =
        buildList {
            repeat(minOf(limit, callbacks.size)) { add(callbacks.removeFirst()) }
        }

    fun complete(result: Result<T>) {
        take(Int.MAX_VALUE).forEach { callback -> runCatching { callback(result) } }
    }

    @Synchronized
    fun size(): Int = callbacks.size
}
