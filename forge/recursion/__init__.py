"""Recursion intents (Cairn Fact/Intent/Hint, Wave 2 #20).

Read-only view + append-only operator writes over the ``recursion_intents``
table. The kill-chain scheduler is not rewritten; these rows are a durable
record of what *would* be recursed if a scheduler or operator claimed the
intent.
"""
