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

    fun complete(result: Result<T>) {
        val ready = synchronized(this) {
            buildList {
                while (callbacks.isNotEmpty()) add(callbacks.removeFirst())
            }
        }
        ready.forEach { callback -> runCatching { callback(result) } }
    }

    @Synchronized
    fun size(): Int = callbacks.size
}
