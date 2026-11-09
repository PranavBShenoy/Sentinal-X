"""
Dependency Graph Builder & NetworkX Analysis Engine.

Loads Software Bill of Materials (SBOM) component and edge records from the database,
constructs a directed graph using NetworkX, traces paths from the root application
to vulnerable components, and prepares visualization payloads.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Set, Tuple

import networkx as nx

from app.core.database import db_session
from app.core.logging import get_logger
from app.models import DependencyEdge, Finding, FindingCategory, SbomComponent

logger = get_logger(__name__)


class DependencyGraphBuilder:
    """Constructs and analyzes application dependency graphs using NetworkX."""

    def build(self, assessment_id: str) -> Dict[str, Any]:
        """
        Build and analyze the dependency graph for an assessment.

        Returns analysis summary and updates SbomComponent.is_direct in DB.
        """
        with db_session() as db:
            components = (
                db.query(SbomComponent)
                .filter(SbomComponent.assessment_id == assessment_id)
                .all()
            )
            edges = (
                db.query(DependencyEdge)
                .filter(DependencyEdge.assessment_id == assessment_id)
                .all()
            )
            vulnerable_findings = (
                db.query(Finding)
                .filter(
                    Finding.assessment_id == assessment_id,
                    Finding.category == FindingCategory.DEPENDENCY,
                )
                .all()
            )

        if not components:
            return {"nodes_count": 0, "edges_count": 0, "vulnerable_paths": []}

        # Build NetworkX DiGraph
        G = nx.DiGraph()
        app_root = "app:root"
        G.add_node(app_root, name="Application Root", type="root", vulnerable=False)

        comp_by_purl: Dict[str, SbomComponent] = {c.purl: c for c in components if c.purl}
        comp_by_name: Dict[str, SbomComponent] = {c.name.lower(): c for c in components if c.name}

        # Identify vulnerable component names / purls
        vuln_pkg_names = {f.component.lower() for f in vulnerable_findings if f.component}

        # Add component nodes
        for purl, comp in comp_by_purl.items():
            is_vuln = (
                comp.name.lower() in vuln_pkg_names
                or bool(comp.vulnerability_matches)
            )
            G.add_node(
                purl,
                name=comp.name,
                version=comp.version or "",
                ecosystem=comp.ecosystem or "",
                vulnerable=is_vuln,
                type="package",
            )

        # Add edges
        explicit_targets: Set[str] = set()
        for edge in edges:
            G.add_edge(edge.source_purl, edge.target_purl, relationship=edge.relationship_type)
            explicit_targets.add(edge.target_purl)

        # Connect top-level / direct dependencies to app root
        direct_purls: Set[str] = set()
        for purl in comp_by_purl:
            # Nodes with in-degree 0 (or not targeted by another package) are direct dependencies
            if purl not in explicit_targets:
                G.add_edge(app_root, purl, relationship="direct_dependency")
                direct_purls.add(purl)

        # If no explicit edges were present (e.g. flat manifest like requirements.txt),
        # all components are treated as direct dependencies
        if not edges:
            for purl in comp_by_purl:
                G.add_edge(app_root, purl, relationship="direct_dependency")
                direct_purls.add(purl)

        # Update is_direct classification in database
        with db_session() as db:
            for purl, is_dir in [(p, p in direct_purls) for p in comp_by_purl]:
                c_record = (
                    db.query(SbomComponent)
                    .filter(SbomComponent.assessment_id == assessment_id, SbomComponent.purl == purl)
                    .first()
                )
                if c_record:
                    c_record.is_direct = is_dir

        # Trace paths from app_root to vulnerable packages
        vulnerable_paths: List[List[str]] = []
        for node in G.nodes():
            if G.nodes[node].get("vulnerable", False) and node != app_root:
                try:
                    if nx.has_path(G, app_root, node):
                        all_paths = list(nx.all_simple_paths(G, app_root, node, cutoff=5))
                        for p in all_paths[:3]:  # Limit to 3 shortest paths per vuln
                            # Format as package names for readability
                            readable_path = [
                                G.nodes[n].get("name", n) for n in p
                            ]
                            vulnerable_paths.append(readable_path)
                except Exception:
                    pass

        return {
            "nodes_count": G.number_of_nodes(),
            "edges_count": G.number_of_edges(),
            "direct_count": len(direct_purls),
            "transitive_count": len(comp_by_purl) - len(direct_purls),
            "vulnerable_paths": vulnerable_paths,
        }

    def get_visualization_payload(self, assessment_id: str) -> Dict[str, Any]:
        """Generate structured JSON payload for React dependency graph viewer."""
        with db_session() as db:
            components = (
                db.query(SbomComponent)
                .filter(SbomComponent.assessment_id == assessment_id)
                .all()
            )
            edges = (
                db.query(DependencyEdge)
                .filter(DependencyEdge.assessment_id == assessment_id)
                .all()
            )
            findings = (
                db.query(Finding)
                .filter(
                    Finding.assessment_id == assessment_id,
                    Finding.category == FindingCategory.DEPENDENCY,
                )
                .all()
            )

            vuln_map: Dict[str, List[str]] = {}
            for f in findings:
                if f.component:
                    c_lower = f.component.lower()
                    vuln_map.setdefault(c_lower, []).append(f.rule_id or "CVE")

            nodes = [
                {
                    "id": "app_root",
                    "label": "Application",
                    "type": "root",
                    "is_direct": True,
                    "vulnerable": False,
                    "vulnerabilities": [],
                }
            ]

            purl_to_id: Dict[str, str] = {}
            for idx, comp in enumerate(components):
                node_id = f"pkg_{idx}"
                if comp.purl:
                    purl_to_id[comp.purl] = node_id

                c_vulns = vuln_map.get(comp.name.lower(), [])
                if comp.vulnerability_matches:
                    for vm in comp.vulnerability_matches:
                        if isinstance(vm, dict) and vm.get("id"):
                            c_vulns.append(vm["id"])

                nodes.append({
                    "id": node_id,
                    "label": comp.name,
                    "version": comp.version or "",
                    "ecosystem": comp.ecosystem or "",
                    "purl": comp.purl or "",
                    "is_direct": comp.is_direct if comp.is_direct is not None else True,
                    "vulnerable": len(c_vulns) > 0,
                    "vulnerabilities": list(set(c_vulns)),
                })

            graph_edges = []
            for edge in edges:
                src = purl_to_id.get(edge.source_purl)
                tgt = purl_to_id.get(edge.target_purl)
                if src and tgt:
                    graph_edges.append({"source": src, "target": tgt, "type": edge.relationship_type})

            # Connect direct deps to app_root
            for n in nodes:
                if n["id"] != "app_root" and n.get("is_direct", False):
                    graph_edges.append({"source": "app_root", "target": n["id"], "type": "depends_on"})

            return {"nodes": nodes, "edges": graph_edges}
