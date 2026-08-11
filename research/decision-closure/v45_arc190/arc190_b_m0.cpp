#include <bits/stdc++.h>
using namespace std;
static const long long MOD=998244353;

struct Shape{ vector<pair<int,int>> cells; };
int N,a0,b0,Q;
vector<int> queries;
vector<vector<Shape>> shapes;
vector<vector<vector<unsigned long long>>> masks;
vector<unsigned long long> occ;
vector<long long> cnt;

bool disjointMask(const vector<unsigned long long>& m){
    for(size_t k=0;k<m.size();k++) if(occ[k]&m[k]) return false;
    return true;
}
void addMask(const vector<unsigned long long>& m){ for(size_t k=0;k<m.size();k++) occ[k]|=m[k]; }
void remMask(const vector<unsigned long long>& m){ for(size_t k=0;k<m.size();k++) occ[k]^=m[k]; }

void dfs(int K, vector<int>& chosenTarget){
    if(K==0){
        for(int k=1;k<=N;k++) if(chosenTarget[k]) cnt[k]=(cnt[k]+1)%MOD;
        return;
    }
    for(size_t s=0;s<shapes[K].size();s++){
        const auto &m=masks[K][s];
        if(!disjointMask(m)) continue;
        addMask(m);
        int hit=0;
        for(auto [r,c]:shapes[K][s].cells) if(r==a0 && c==b0){hit=1;break;}
        chosenTarget[K]=hit;
        dfs(K-1,chosenTarget);
        chosenTarget[K]=0;
        remMask(m);
    }
}

int main(){
    ios::sync_with_stdio(false);
    cin.tie(nullptr);
    if(!(cin>>N>>a0>>b0)) return 0;
    --a0; --b0;
    cin>>Q; queries.resize(Q);
    for(int&i:queries)cin>>i;
    shapes.assign(N+1,{});
    masks.assign(N+1,{});
    int W=(N*N+63)/64;
    for(int K=1;K<=N;K++){
        set<vector<pair<int,int>>> uniq;
        for(int r=0;r<N;r++) for(int c=0;c<N;c++){
            for(int vr: {-1,1}) for(int hc:{-1,1}){
                vector<pair<int,int>> v;
                bool ok=true;
                for(int t=0;t<K;t++){
                    int rr=r+vr*t, cc=c;
                    if(rr<0||rr>=N){ok=false;break;}
                    v.push_back({rr,cc});
                }
                if(!ok) continue;
                for(int t=1;t<K;t++){
                    int rr=r, cc=c+hc*t;
                    if(cc<0||cc>=N){ok=false;break;}
                    v.push_back({rr,cc});
                }
                if(!ok) continue;
                sort(v.begin(),v.end());
                uniq.insert(v);
            }
        }
        for(auto &v:uniq){
            shapes[K].push_back(Shape{v});
            vector<unsigned long long> m(W);
            for(auto [r,c]:v){ int id=r*N+c; m[id>>6]|=1ULL<<(id&63); }
            masks[K].push_back(move(m));
        }
    }
    occ.assign(W,0);
    cnt.assign(N+1,0);
    vector<int> chosenTarget(N+1);
    dfs(N,chosenTarget);
    for(int k:queries) cout<<cnt[k]%MOD<<'\n';
}
