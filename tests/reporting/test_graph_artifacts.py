import zipfile
from pathlib import Path
from xml.etree import ElementTree

from forge.reporting.graph_artifacts import (
    graph_files,
    graph_payload_from_graphml,
    graph_payload_from_root,
)


def test_graph_files_returns_existing_manifest_artifacts_sorted(tmp_path: Path) -> None:
    reports_dir = tmp_path / "reports"
    reports_dir.mkdir()
    for name in (
        "1001_attack_graph_nodes.csv",
        "1001_attack_graph.graphml",
        "1001_attack_graph.mtgx",
        "unrelated.graphml",
    ):
        (reports_dir / name).write_text("", encoding="utf-8")

    files = graph_files("1001", reports_dir)

    assert [path.name for path in files] == [
        "1001_attack_graph.graphml",
        "1001_attack_graph.mtgx",
        "1001_attack_graph_nodes.csv",
    ]


def test_graph_payload_from_root_maps_graphml_nodes_edges_and_metadata() -> None:
    root = ElementTree.fromstring(
        """
        <graphml xmlns="http://graphml.graphdrawing.org/xmlns">
          <graph id="G" edgedefault="directed">
            <node id="n1">
              <data key="label">app.acme.example</data>
              <data key="entity_type">HOST</data>
              <data key="severity">HIGH</data>
              <data key="critical">1</data>
              <data key="source_table">hosts</data>
              <data key="source_id">12</data>
              <data key="metadata_json">{"seed_type":"url","api_key":"hidden"}</data>
            </node>
            <node id="n2">
              <data key="label">storage bucket</data>
              <data key="node_type">CLOUD</data>
            </node>
            <edge source="n1" target="n2">
              <data key="relation">exposes</data>
              <data key="weight">55</data>
              <data key="edge_metadata_json">{"rule":"validated_cloud_edge","key_enc":"hidden"}</data>
            </edge>
          </graph>
        </graphml>
        """.strip()
    )

    payload = graph_payload_from_root(
        root,
        source="fixture.graphml",
        generated_at="2026-08-12 01:02:03",
    )

    assert payload is not None
    assert payload["source"] == "fixture.graphml"
    assert payload["generated_at"] == "2026-08-12 01:02:03"
    assert payload["critical_path_nodes"] == ["n1"]
    assert payload["nodes"][0]["node_id"] == "n1"
    assert payload["nodes"][0]["label"] == "app.acme.example"
    assert payload["nodes"][0]["node_type"] == "HOST"
    assert payload["nodes"][0]["source_table"] == "hosts"
    assert payload["nodes"][0]["source_id"] == 12
    assert payload["nodes"][0]["metadata"] == {"seed_type": "url"}
    assert payload["edges"][0]["edge_type"] == "exposes"
    assert payload["edges"][0]["weight"] == 55.0
    assert payload["edges"][0]["metadata"] == {"rule": "validated_cloud_edge"}


def test_graph_payload_from_graphml_reads_mtgx_and_sanitizes_forge_properties(
    tmp_path: Path,
) -> None:
    mtgx_path = tmp_path / "1001_attack_graph.mtgx"
    graphml = """
    <graphml xmlns="http://graphml.graphdrawing.org/xmlns" xmlns:mtg="http://maltego.paterva.com/xml/mtgx">
      <graph id="G" edgedefault="directed">
        <node id="n1">
          <data key="mtg_entity">
            <mtg:MaltegoEntity type="maltego.Domain">
              <mtg:Properties>
                <mtg:Property name="fqdn" type="string"><mtg:Value>app.acme.example</mtg:Value></mtg:Property>
                <mtg:Property name="forge.label" type="string"><mtg:Value>app.acme.example</mtg:Value></mtg:Property>
                <mtg:Property name="forge.node_type" type="string"><mtg:Value>HOST</mtg:Value></mtg:Property>
                <mtg:Property name="forge.severity" type="string"><mtg:Value>LOW</mtg:Value></mtg:Property>
                <mtg:Property name="forge.source_table" type="string"><mtg:Value>hosts</mtg:Value></mtg:Property>
                <mtg:Property name="forge.source_id" type="string"><mtg:Value>12</mtg:Value></mtg:Property>
                <mtg:Property name="forge.on_critical_path" type="string"><mtg:Value>1</mtg:Value></mtg:Property>
                <mtg:Property name="forge.validation_detail" type="string"><mtg:Value>VALIDATED:firebase_database_shallow_read:Firebase project reference responded with non-empty data.</mtg:Value></mtg:Property>
                <mtg:Property name="forge.key_enc" type="string"><mtg:Value>encrypted-secret-never-render</mtg:Value></mtg:Property>
                <mtg:Property name="forge.metadata_json" type="string"><mtg:Value>{"seed_type":"url","source":"mtgx-fixture","token":"hidden"}</mtg:Value></mtg:Property>
              </mtg:Properties>
            </mtg:MaltegoEntity>
          </data>
        </node>
        <node id="n2">
          <data key="mtg_entity">
            <mtg:MaltegoEntity type="maltego.Alias">
              <mtg:Properties>
                <mtg:Property name="alias" type="string"><mtg:Value>storage bucket</mtg:Value></mtg:Property>
                <mtg:Property name="forge.node_type" type="string"><mtg:Value>CLOUD</mtg:Value></mtg:Property>
              </mtg:Properties>
            </mtg:MaltegoEntity>
          </data>
        </node>
        <edge id="e1" source="n1" target="n2">
          <data key="mtg_link">
            <mtg:MaltegoLink type="maltego.link.manual-link">
              <mtg:Properties>
                <mtg:Property name="maltego.link.manual.type" type="string"><mtg:Value>exposes</mtg:Value></mtg:Property>
                <mtg:Property name="forge.weight" type="string"><mtg:Value>55</mtg:Value></mtg:Property>
                <mtg:Property name="forge.metadata_json" type="string"><mtg:Value>{"rule":"validated_cloud_edge","key_enc":"hidden"}</mtg:Value></mtg:Property>
              </mtg:Properties>
            </mtg:MaltegoLink>
          </data>
        </edge>
      </graph>
    </graphml>
    """
    with zipfile.ZipFile(mtgx_path, "w") as archive:
        archive.writestr("Graphs/Graph1.graphml", graphml.strip())

    payload = graph_payload_from_graphml(mtgx_path)

    assert payload is not None
    assert payload["source"] == "1001_attack_graph.mtgx"
    assert payload["nodes"][0]["label"] == "app.acme.example"
    assert payload["nodes"][0]["node_type"] == "HOST"
    assert payload["nodes"][0]["source_table"] == "hosts"
    assert payload["nodes"][0]["source_id"] == 12
    assert payload["nodes"][0]["on_critical_path"] is True
    assert payload["nodes"][0]["metadata"]["seed_type"] == "url"
    assert payload["nodes"][0]["metadata"]["source"] == "mtgx-fixture"
    assert payload["nodes"][0]["metadata"]["validation_status"] == "VALIDATED"
    assert payload["nodes"][0]["metadata"]["validation_method"] == (
        "firebase_database_shallow_read"
    )
    assert "key_enc" not in payload["nodes"][0]["metadata"]
    assert "token" not in payload["nodes"][0]["metadata"]
    assert payload["edges"][0]["edge_type"] == "exposes"
    assert payload["edges"][0]["weight"] == 55.0
    assert payload["edges"][0]["metadata"] == {"rule": "validated_cloud_edge"}
