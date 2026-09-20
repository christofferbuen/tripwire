"""Build an auditable overlay on the pinned upstream revision, never live config."""
import argparse
from pathlib import Path
import shutil
import subprocess
import tempfile

REVISION = '16536500b6b96840675e08aded74af14c22619a8'
HERE = Path(__file__).resolve().parent

def replace(path, before, after):
    text = path.read_text(encoding='utf-8')
    if text.count(before) != 1:
        raise ValueError('upstream patch anchor changed: ' + path.name)
    path.write_text(text.replace(before, after), encoding='utf-8', newline='\n')

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, default=HERE.parent / '.beelzebub.local.source')
    parser.add_argument('--tag', default='localhost/tripwire-beelzebub:session-v1')
    args=parser.parse_args()
    revision=subprocess.check_output(['git','-C',str(args.source),'rev-parse','HEAD'],text=True).strip()
    if revision != REVISION: raise SystemExit('Unexpected upstream revision')
    with tempfile.TemporaryDirectory(prefix='tripwire-engine-') as temporary:
        root=Path(temporary)
        # Export committed source only; never include ignored configuration or keys.
        archive=subprocess.check_output(['git','-C',str(args.source),'archive',REVISION])
        import io,tarfile
        with tarfile.open(fileobj=io.BytesIO(archive)) as stream: stream.extractall(root,filter='data')
        ssh=root/'internal/protocols/strategies/SSH'
        for source in (HERE/'engine').glob('*.go'): shutil.copyfile(source,ssh/source.name)
        replace(ssh/'ssh.go','"context"','"context"\n"os"')
        replace(ssh/'ssh.go','Handler: func(sess ssh.Session) {','Handler: func(sess ssh.Session) {\nif os.Getenv("TRIPWIRE_SHELL") == "1" { handleTripwire(sess, servConf, tr); return }')
        llm=root/'internal/plugins/llm-integration.go'
        replace(llm,'"encoding/json"','"encoding/json"\n"context"\n"time"')
        replace(llm,'type LLMHoneypot struct {','type LLMHoneypot struct {\nContext context.Context')
        replace(llm,'config.client = resty.New()','config.client = resty.New().SetTimeout(32*time.Second)\nif config.Context == nil { config.Context = context.Background() }')
        # Both provider calls get cancellation, with no retries or extra spend.
        content=llm.read_text(encoding='utf-8')
        assert content.count('llmHoneypot.client.R().')==2
        content=content.replace('llmHoneypot.client.R().','llmHoneypot.client.R().SetContext(llmHoneypot.Context).')
        content=content.replace('log.Debug(string(requestJSON))','// Request contents intentionally omitted from diagnostics.')
        content=content.replace('log.Debug(response)','// Provider contents intentionally omitted from diagnostics.')
        llm.write_text(content,encoding='utf-8',newline='\n')
        replace(root/'internal/plugins/llm_adapter.go','hp := &LLMHoneypot{','hp := &LLMHoneypot{\nContext: ctx,')
        shutil.copyfile(HERE/'engine/Containerfile',root/'Containerfile.tripwire')
        subprocess.run(['podman','build','-t',args.tag,'-f',str(root/'Containerfile.tripwire'),str(root)],check=True)

if __name__=='__main__': main()
