#include <bits/stdc++.h>
using namespace std;
using int64 = long long;

struct Fenwick {
    int n;
    vector<int> bit;
    Fenwick(int n=0): n(n), bit(n+1,0) {}
    void add(int i,int v){ for(;i<=n;i+=i&-i) bit[i]+=v; }
    int sumPrefix(int i) const {
        int s=0;
        for(;i>0;i-=i&-i) s+=bit[i];
        return s;
    }
};

struct Event {
    int x, y, id, coef;
    bool operator<(Event const& other) const {
        return x < other.x;
    }
};

int main(){
    ios::sync_with_stdio(false);
    cin.tie(nullptr);

    int T;
    cin >> T;
    const int64 INF = (1LL<<62);

    while(T--){
        int N;
        int64 K;
        cin >> N >> K;
        vector<int> A(N+1), B(N+1);
        for(int i=1;i<=N;i++) cin >> A[i];
        for(int i=1;i<=N;i++) cin >> B[i];

        vector<vector<int>> target(N+1), source(N+1);
        for(int i=1;i<=N;i++){
            target[B[i]].push_back(i);
            source[A[i]].push_back(i);
        }
        vector<int> ptr(N+1,0), p(N+1);
        for(int i=1;i<=N;i++){
            int v=A[i];
            p[i]=target[v][ptr[v]++];
        }

        Fenwick invbit(N);
        int64 inv=0;
        for(int i=N;i>=1;i--){
            inv += invbit.sumPrefix(p[i]-1);
            invbit.add(p[i],1);
        }

        struct PairQ { int l,r,a,b; };
        vector<PairQ> qs;
        bool hasDup=false;
        for(int v=1;v<=N;v++){
            auto &s=source[v];
            if((int)s.size()>=2) hasDup=true;
            for(int t=0;t+1<(int)s.size();t++){
                int l=s[t], r=s[t+1];
                qs.push_back({l,r,p[l],p[r]});
            }
        }

        int64 minDelta=INF;
        if(hasDup){
            vector<Event> ev;
            ev.reserve(qs.size()*4);
            vector<int> cnt(qs.size(),0);
            auto addEvent = [&](int x,int y,int id,int coef){
                if(x<0) x=0;
                if(y<0) y=0;
                ev.push_back({x,y,id,coef});
            };
            for(int id=0;id<(int)qs.size();id++){
                auto [l,r,a,b]=qs[id];
                addEvent(r-1,b-1,id,+1);
                addEvent(l,b-1,id,-1);
                addEvent(r-1,a,id,-1);
                addEvent(l,a,id,+1);
            }
            sort(ev.begin(),ev.end());
            Fenwick fw(N);
            int cur=0;
            for(auto &e:ev){
                while(cur<e.x){
                    ++cur;
                    fw.add(p[cur],1);
                }
                cnt[e.id] += e.coef * fw.sumPrefix(e.y);
            }
            for(int id=0;id<(int)qs.size();id++){
                minDelta=min(minDelta, 1LL + 2LL*cnt[id]);
            }
        }

        int64 minLen[2]={INF,INF};
        minLen[inv&1]=inv;
        if(hasDup) minLen[(inv&1)^1]=inv+minDelta;

        int64 ans=INF;
        for(int par=0;par<2;par++){
            if(minLen[par]==INF) continue;
            int64 c=(minLen[par]+K-1)/K;
            if((K&1)==0){
                if(par==1) continue;
            }else{
                if((c&1)!=par) ++c;
            }
            ans=min(ans,c);
        }

        if(ans==INF) cout << -1 << '\n';
        else cout << ans << '\n';
    }
    return 0;
}
