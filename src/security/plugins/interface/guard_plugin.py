"""GuardPlugin Interface — 9/22 frozen contract.

Every Guard (Input/Context/Tool/Output, plus any future Guard) implements
this interface. The Orchestrator must be able to add or swap a Guard purely
by registering it — no Orchestrator code changes required (P0 Done
criterion).
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from enums import Stage
from schemas import RuntimeObservation, SecurityContext, SecurityResult


class GuardPlugin(ABC):
    """Base interface every Guard plugin must implement."""

    #: Unique, stable name used for registration and in SecurityResult.guard_name
    name: str

    #: Which pipeline stage this Guard runs at
    stage: Stage

    @abstractmethod
    def inspect(
        self,
        observation: RuntimeObservation,
        context: SecurityContext,
    ) -> SecurityResult:
        """Run this Guard's check and return a SecurityResult.

        Implementations should NOT raise on "the input looks risky" — that's
        a normal BLOCK/WARN SecurityResult. Raising should be reserved for
        genuine execution failures (bugs, unavailable dependencies); the
        PluginManager wraps calls with a timeout/error boundary and converts
        any raised exception into GuardExecutionStatus.ERROR, per the Guard
        Failure Isolation rules — implementations do not need to handle that
        themselves.
        """
        raise NotImplementedError

    def sanitize(
        self,
        observation: RuntimeObservation,
        context: SecurityContext,
    ) -> SecurityResult:
        """Called instead of inspect() on a sanitize-and-recheck attempt
        (STRICT+WARN at OUTPUT stage). Default: no real sanitization
        capability, just re-check as-is. Guards that can actually redact
        content should override this.
        """
        return self.inspect(observation, context)
