#include <bits/stdc++.h>
using namespace std;

// ARC207 E - X1
// Frozen feedback: s=001 -> t=011 is reachable in one operation (3,2),
// while M0 rejected it because M0 forced contraction all the way to one root.
// Bounded correction: first recognize every exact 0/1-operation solution in
// O(N), then fall back to the frozen contraction construction unchanged.

struct Fenwick {
    int n; vector<int> bit;
    Fenwick(int n=0): n(n), bit(n+1,0) {}
    void add(int i,int v){ for(;i<=n;i+=i&-i) bit[i]+=v; }
    int sum(int i) const { int r=0; for(;i>0;i-=i&-i) r+=bit[i]; return r; }
};

int main(){
    ios::sync_with_stdio(false);
    cin.tie(nullptr);

    int T; cin >> T;
    while(T--){
        int N; string s,t;
        cin >> N >> s >> t;

        if(s==t){
            cout << 0 << '\n';
            continue;
        }

        vector<char> pref(N+1,0), shift(N+1,0);
        pref[0]=1;
        for(int k=1;k<=N;k++) pref[k]=pref[k-1] && (s[k-1]==t[k-1]);

        shift[N-1]=1;
        shift[N]=1;
        for(int p=N-2;p>=0;--p)
            shift[p]=shift[p+1] && (t[p]==s[p+1]);

        bool direct=false;
        pair<int,int> direct_op{-1,-1};
        for(int i=0;i+1<N && !direct;i++){
            if(pref[i+1] && shift[i+1] && t[N-1]==s[i]){
                direct=true;
                direct_op={i+1,i+2};
                break;
            }
            if(pref[i] && shift[i] && t[N-1]==s[i+1]){
                direct=true;
                direct_op={i+2,i+1};
                break;
            }
        }
        if(direct){
            cout << 1 << '\n' << direct_op.first << ' ' << direct_op.second << '\n';
            continue;
        }

        vector<int> col(N+1), prv(N+1), nxt(N+1);
        vector<char> alive(N+1,1);
        for(int i=1;i<=N;i++){
            col[i]=s[i-1]-'0';
            prv[i]=i-1;
            nxt[i]=(i==N?0:i+1);
        }

        set<int> ed[2][2];
        auto add_edge = [&](int u,int v){
            if(u && v) ed[col[u]][col[v]].insert(u);
        };
        auto del_edge = [&](int u,int v){
            if(u && v) ed[col[u]][col[v]].erase(u);
        };
        for(int i=1;i<N;i++) add_edge(i,i+1);

        int cnt[2]={0,0};
        for(char c:s) cnt[c-'0']++;
        int future[2]={0,0};
        for(int i=1;i<N;i++) future[t[i]-'0']++;

        Fenwick fw(N);
        for(int i=1;i<=N;i++) fw.add(i,1);

        vector<pair<int,int>> ops;
        bool ok=true;

        auto choose_cross = [&](int q, int &killer, int &victim)->bool{
            int o=q^1;
            if(!ed[q][o].empty()){
                int u=*ed[q][o].begin();
                killer=u; victim=nxt[u];
                return true;
            }
            if(!ed[o][q].empty()){
                int u=*ed[o][q].begin();
                victim=u; killer=nxt[u];
                return true;
            }
            return false;
        };
        auto choose_same = [&](int q, int &killer, int &victim)->bool{
            if(ed[q][q].empty()) return false;
            int u=*ed[q][q].begin();
            killer=u; victim=nxt[u];
            return true;
        };

        for(int step=1; step<N && ok; ++step){
            int q=t[step]-'0';
            --future[q];
            int o=q^1;
            bool other_needed = (future[o]>0 || (t[0]-'0')==o);

            int killer=0, victim=0;
            if(cnt[o]>0 && !(cnt[o]==1 && other_needed)){
                if(!choose_cross(q,killer,victim)){ ok=false; break; }
            }else{
                if(!choose_same(q,killer,victim)){ ok=false; break; }
            }

            int a=fw.sum(killer);
            int b=fw.sum(victim);
            if(abs(a-b)!=1){ ok=false; break; }
            ops.push_back({a,b});

            int p=prv[victim], n=nxt[victim];
            del_edge(p,victim);
            del_edge(victim,n);
            if(p) nxt[p]=n;
            if(n) prv[n]=p;
            add_edge(p,n);

            alive[victim]=0;
            fw.add(victim,-1);
            --cnt[col[victim]];
        }

        int root=0;
        if(ok){
            for(int i=1;i<=N;i++) if(alive[i]) { root=col[i]; break; }
            if(root != t[0]-'0' || (int)ops.size()>N+1) ok=false;
        }

        if(!ok){
            cout << -1 << '\n';
        }else{
            cout << ops.size() << '\n';
            for(auto [a,b]:ops) cout << a << ' ' << b << '\n';
        }
    }
    return 0;
}
