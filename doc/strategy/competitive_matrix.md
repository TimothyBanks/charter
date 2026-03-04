# Charter Competitive Matrix (Direct / Adjacent / Future Threat)

As of: March 1, 2026  
Use: funding deck + partner conversations  
Note: This matrix is based on public product positioning. Rows labeled `Inference`
reflect strategic interpretation, not confirmed product roadmap.

## Positioning Lens

Charter target design:
- custody-native protocol state machine (policy execution on-chain)
- permissioned validator set with institutional accountability
- public-read transparency, permissioned write/finality
- transaction-fee-first economics

Boundary reminder:
- Charter wedge: regulated institutional custody governance and evidence.
- Not the same wedge as permissionless self-custody wallet/builder ecosystems.

## 1) Direct (Closest Strategic Shape)

| Player | Public Signals (Source-backed) | Overlap With Charter | Gap vs Charter (or Open Question) | Competitive Pressure |
|---|---|---|---|---|
| Canton Network ecosystem (Canton Foundation + validator ecosystem) | Canton publishes validator onboarding, approved Node-as-a-Service operators, and minimum operational requirements for hosted validators; validator application includes sponsor/super-validator path. | Institutional validator network model; operational standards; custody-heavy participant ecosystem. | `Inference:` public materials emphasize network/validator operations and ecosystem access. Charter's differentiator remains custody workflow policy execution as the primary protocol surface. | High |
| Kinexys by J.P. Morgan | J.P. Morgan positions Kinexys as bank-led blockchain infrastructure for payments/tokenization, with 24/7 near real-time settlement and large institutional transaction volume. | Institutional-grade blockchain rails for regulated financial workflows. | `Inference:` Kinexys is currently framed as bank-led financial infrastructure, not an open custody-policy protocol. If it expands deeper into custody governance workflows, overlap increases materially. | Medium-High |

## 2) Adjacent (Strong Capability Overlap, Different Product Form)

| Player | Public Signals (Source-backed) | Overlap With Charter | Current Difference | Pressure |
|---|---|---|---|---|
| Fireblocks | Policy engine with approval workflows, compliance integrations, API automation, and off-exchange capabilities. | Governance controls, policy workflows, institutional operations tooling. | Primarily infrastructure/platform layer rather than a custody-specific L1 protocol with protocol-native validator economics. | High |
| BitGo (Qualified Custody + Go Network) | Qualified custody, MPC/multi-sig, regulated custody entities, settlement network with DvP and off-exchange settlement while maintaining custody. | Institutional custody + settlement + regulated posture. | Primarily custody/settlement infrastructure; not presented as custody-policy state machine blockchain. | High |
| Anchorage Digital | Federally chartered crypto bank positioning, qualified custodian framing, institutional authorization controls and auditable custody. | Regulated custody and institutional trust/compliance positioning. | Bank/custodian model rather than protocol-native custody control chain. | Medium-High |
| Coinbase Prime Custody | Qualified custodian entity, institutional policy engine controls, governance/staking from custody, broad institutional platform integration. | Institutional custody + governance controls + policy tooling. | Platform/custodian form factor versus custody-native protocol governance as the core product. | Medium-High |
| Kraken Custody | Qualified custody from licensed Kraken Financial, policy enforcement, segregated on-chain vault monitoring, integrated OTC access. | Institutional custody controls, policy enforcement, compliance posture. | Custody platform model; no public positioning as custody-specific validator-governed protocol. | Medium |
| Copper (ClearLoop) | Off-exchange settlement with MPC custody, institutional custody + collateral management focus. | Institutional custody/settlement pain points overlap strongly. | Settlement and custody infrastructure focus versus custody-policy blockchain protocol layer. | Medium |
| Zenrock (zrChain / dMPC ecosystem) | Public materials describe a permissionless dMPC ecosystem with a purpose-built L1 (`zrChain`), decentralized custody tokens (e.g., `zenBTC`), and builder-focused cross-chain custody/security tooling. | "Custody on-chain" narrative and protocol-native custody/security infrastructure. | Charter is currently differentiated by institutional custody workflow scope (explicit policy + governance + compliance process modeling) and permissioned validator/licensing intent. Zenrock's public emphasis is permissionless builder ecosystem + tokenized product growth. | Medium |

GitHub activity note:
- `Inference:` some legacy/fork repos appear archived under `zenrocklabs`, but current project activity appears centered under `Zenrock-Foundation` repositories.
- As of March 1, 2026 public GitHub pages showed:
  - `Zenrock-Foundation`: 1 primary public repo (`zrchain`), updated Jan 23, 2026.
  - `zenrocklabs`: mixed activity; several updates in Jan-Feb 2026, with multiple repos being forks/archived.
- `Inference:` this is not "dead", but repository breadth is narrow and activity concentration risk should be tracked.

## 3) Future Threats (Inference)

| Threat Theme | Why It Matters | Trigger Signals To Watch | Impact if Triggered |
|---|---|---|---|
| Custody platforms verticalize into protocol rails | Leading custodians already bundle custody + policy + settlement. Adding a validator-governed workflow ledger is a plausible extension. | Launch of permissioned chain/appchain products, validator programs, or on-chain policy state models by major custodians. | High |
| Canton ecosystem converges on custody-policy standard | Canton already has many custody and NaaS operators in one network context. A standardized custody workflow layer could emerge quickly. | New Canton app standards for custody policy lifecycle, regulator evidence APIs, or native institutional governance modules. | High |
| Bank-led tokenization/payment networks expand into custody governance | Large banks have distribution and regulatory capacity to absorb adjacent workflow layers. | Public roadmap language adding custody policy orchestration, approval workflows, or compliance evidence rails. | Medium-High |

## 4) Deck Narrative Guidance

- Claim carefully: "competition exists in adjacent layers; no clear public 1:1 match on custody-native policy-as-protocol architecture" (`Inference`).
- Keep wedge explicit: Charter is not "better custody UX"; it is protocolized custody governance.
- Defend moat with evidence:
  - deterministic policy execution contract
  - replayable audit/evidence model
  - regulator-facing workflow clarity

## Sources

1. Fireblocks governance/policy engine:  
   https://www.fireblocks.com/platforms/governance-and-policy-engine/
2. Anchorage custody:  
   https://www.anchorage.com/platform/custody
3. BitGo qualified custody:  
   https://www.bitgo.com/products/qualified-custody/
4. BitGo Go Network settlement:  
   https://www.bitgo.com/products/go-network/
5. BitGo support for Canton Coin custody:  
   https://www.bitgo.com/resources/blog/canton-coin-is-now-available-for-custody-on-bitgo/
6. Copper platform / ClearLoop positioning:  
   https://copper.co/
7. Canton validator access + requirements:  
   https://canton.foundation/validators/
8. Canton validator application flow:  
   https://canton.foundation/apply-to-set-up-a-validator-node/
9. Coinbase Prime custody:  
   https://www.coinbase.com/prime/custody
10. Kraken Custody:  
    https://custody.kraken.com/
11. Kinexys by J.P. Morgan overview:  
    https://www.jpmorgan.com/insights/payments/blockchain-digital-assets/introducing-kinexys
12. Zenrock docs overview (zrChain, dMPC, DCT model):  
    https://docs.zenrocklabs.io/
13. Zenrock foundation/company positioning:  
    https://www.zenrockfoundation.io/about/company
14. Zenrock Foundation `zrchain` repo (active project history):  
    https://github.com/Zenrock-Foundation/zrchain
15. Zenrock Labs org (includes archived forks such as `zenrocklabs/zrchain`):  
    https://github.com/zenrocklabs
