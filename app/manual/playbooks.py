"""Business logic test plans. A tester performs each step by hand, using test data only."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Playbook:
    key: str
    title: str
    test_case: str
    objective: str
    preconditions: str
    remediation: str
    steps: tuple[tuple[str, str], ...]


_TEST_DATA = "Test accounts, sandbox payment details and client-approved test records are available."

PLAYBOOKS = {
    item.key: item
    for item in (
        Playbook(
            "price_manipulation", "Price manipulation", "WSTG-BUSL-03",
            "Confirm that the server calculates every price and total.",
            _TEST_DATA,
            "Calculate prices and totals on the server from trusted catalogue data.",
            (("Add a test item to the basket and record the displayed price.", "The price matches the catalogue."),
             ("Review which price-related values the client sends during checkout.", "Totals are not accepted from the client."),
             ("In the sandbox, change a client-supplied price value before the order is placed.", "The server rejects the change or recalculates the correct price."),
             ("Compare the final sandbox order with the catalogue price.", "The recorded total is correct.")),
        ),
        Playbook(
            "payment_bypass", "Payment workflow bypass", "WSTG-BUSL-06",
            "Confirm that orders cannot be completed without a successful payment.",
            _TEST_DATA,
            "Fulfil orders only after the payment provider's verified server-side confirmation.",
            (("Start a sandbox order and record each checkout step.", "Each step is listed in order."),
             ("Request the order confirmation step before completing payment.", "The application refuses and returns to payment."),
             ("Abandon a sandbox payment and review the order state.", "The order stays unpaid and is not fulfilled."),
             ("Review how payment success is communicated to the application.", "Success is verified server to server.")),
        ),
        Playbook(
            "coupon_abuse", "Coupon abuse", "WSTG-BUSL-05",
            "Confirm that discount rules and usage limits are enforced.",
            _TEST_DATA,
            "Enforce coupon eligibility, limits and stacking rules on the server.",
            (("Apply a client-provided test coupon and record the discount.", "The discount matches the coupon's rules."),
             ("Apply the same test coupon a second time to the order.", "The second use is refused."),
             ("Use a single-use test coupon on a second test order.", "The coupon is refused."),
             ("Combine test coupons that should not stack.", "Only permitted combinations are accepted.")),
        ),
        Playbook(
            "transaction_replay", "Transaction replay", "WSTG-BUSL-04",
            "Confirm that a completed transaction cannot be processed twice.",
            _TEST_DATA,
            "Use idempotency keys and single-use tokens for state-changing transactions.",
            (("Complete one sandbox transaction and record its reference.", "One transaction is recorded."),
             ("Resubmit the completed step once from the browser history.", "The application detects the repeat and does not process it."),
             ("Review the sandbox ledger for that reference.", "Only one transaction exists.")),
        ),
        Playbook(
            "race_condition", "Race conditions", "WSTG-BUSL-04",
            "Review whether limited actions stay correct when performed close together.",
            f"{_TEST_DATA} The client has approved timing tests in a non-production environment.",
            "Use database transactions, locks and unique constraints around limited actions.",
            (("Identify a limited action, such as redeeming a single-use test voucher.", "The limit is documented."),
             ("With the client present, perform the action from two test sessions at nearly the same time.", "Only one action succeeds."),
             ("Review the resulting balance or counter.", "The final value respects the limit.")),
        ),
        Playbook(
            "duplicate_transaction", "Duplicate transactions", "WSTG-BUSL-05",
            "Confirm that accidental repeat submissions do not create duplicates.",
            _TEST_DATA,
            "Apply idempotency controls and disable duplicate processing on the server.",
            (("Submit one sandbox order and record the result.", "One order is created."),
             ("Refresh the confirmation page and accept any resubmission prompt.", "No second order is created."),
             ("Review the order history in the test account.", "Exactly one order is listed.")),
        ),
        Playbook(
            "workflow_bypass", "Workflow bypass", "WSTG-BUSL-06",
            "Confirm that required steps cannot be skipped.",
            _TEST_DATA,
            "Track workflow state on the server and validate it at every step.",
            (("Document each required step of the workflow.", "All steps and their order are listed."),
             ("Open a later step directly without completing the earlier ones.", "The application returns to the correct step."),
             ("Return to an earlier step after completing a later one, and change a value.", "Later steps are revalidated.")),
        ),
        Playbook(
            "balance_manipulation", "Account balance manipulation", "WSTG-BUSL-03",
            "Confirm that balances change only through legitimate transactions.",
            _TEST_DATA,
            "Derive balances from a server-side ledger and validate every amount.",
            (("Record the opening balance of a test account.", "The balance is known."),
             ("In the sandbox, enter out-of-range amounts such as zero or negative values.", "Invalid amounts are rejected."),
             ("Compare the closing balance with the ledger.", "The balance matches the recorded transactions.")),
        ),
        Playbook(
            "reservation_manipulation", "Reservation manipulation", "WSTG-BUSL-07",
            "Confirm that reservations cannot be held or altered unfairly.",
            _TEST_DATA,
            "Limit holds per user, expire them on the server and validate availability at confirmation.",
            (("Create a test reservation and record its hold period.", "The hold period is shown."),
             ("Leave the hold until it should expire.", "The item is released on time."),
             ("Attempt to confirm the expired reservation.", "The confirmation is refused."),
             ("Create test holds up to the documented limit.", "The limit is enforced.")),
        ),
        Playbook(
            "unauthorized_modification", "Unauthorized resource modification", "WSTG-BUSL-03",
            "Confirm that users can change only the records they are allowed to change.",
            "Two test accounts with separate client-approved test records are available.",
            "Check ownership and role on the server for every change.",
            (("Record a test item owned by account A.", "Ownership is clear."),
             ("Signed in as account B, review whether account A's record can be opened for editing.", "Access is refused."),
             ("Confirm that account A's record is unchanged.", "The record is unchanged.")),
        ),
    )
}
