"""Run after installing requirements: python -m pytest -q (pytest separate dev dependency)."""
import app as hf
from pathlib import Path


def test_ioc_must_appear_in_article_and_model_evidence():
    original = 'Sample report: beacon observed contacting 198.51.100.44 on port 443.'
    good = hf.IOC(type='ip',value='198.51.100.44',evidence='contacting 198.51.100.44')
    bad_evidence = hf.IOC(type='ip',value='198.51.100.44',evidence='an unrelated phrase')
    invented = hf.IOC(type='ip',value='203.0.113.15',evidence='contacting 203.0.113.15')
    assert hf.has_literal_evidence(good, original)
    assert not hf.has_literal_evidence(bad_evidence, original)
    assert not hf.has_literal_evidence(invented, original)


def test_reject_local_and_insecure_feed_urls():
    for u in ['http://example.com/rss', 'https://127.0.0.1/rss', 'https://localhost/rss',
              'https://example.local/rss', 'https://example.com:8080/rss']:
        try:
            hf.safe_url(u)
        except ValueError:
            continue
        raise AssertionError(f'Unsafe URL was accepted: {u}')


def test_initial_scan_baselines_then_processes_new_entries(tmp_path, monkeypatch):
    monkeypatch.setattr(hf, 'DATA_DIR', tmp_path)
    monkeypatch.setattr(hf, 'DB', tmp_path / 'hf.sqlite3')
    hf.init_db()
    def feed_xml(last_id):
        items = ''.join(
            f'<item><title>Threat report {i}</title><link>https://public.example/report{i}</link>'
            f'<guid>report{i}</guid><description>Security writeup {i}</description></item>'
            for i in range(1, last_id+1))
        return f'<?xml version="1.0"?><rss version="2.0"><channel><title>Example</title>{items}</channel></rss>'.encode()
    state={'count':1}
    monkeypatch.setattr(hf,'fetch_url',lambda url:(feed_xml(state['count']),url))
    analyzed=[]
    monkeypatch.setattr(hf,'process_article',lambda article_id,title,url,description='': analyzed.append(article_id))
    first=hf.scan_once()
    assert first['new_articles']==3 and first['analyzed']==0
    state['count']=2
    second=hf.scan_once()
    assert second['new_articles']==3 and second['analyzed']==3
    assert len(analyzed)==3
    with hf.connection() as con:
        statuses=[r['status'] for r in con.execute('SELECT status FROM articles')]
    assert statuses.count('baseline')==3
