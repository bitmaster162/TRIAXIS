#include <bits/stdc++.h>
using namespace std;
static const long long MOD=998244353;

long long modpow(long long a,long long e){
    long long r=1;
    while(e){
        if(e&1) r=r*a%MOD;
        a=a*a%MOD;
        e>>=1;
    }
    return r;
}

int main(){
    ios::sync_with_stdio(false);
    cin.tie(nullptr);

    int N;
    string S;
    if(!(cin>>N>>S)) return 0;

    int V=N/2;
    vector<vector<int>> ch(V);
    vector<int> roots, st;
    int id=0;
    for(char c:S){
        if(c=='('){
            int v=id++;
            if(st.empty()) roots.push_back(v);
            else ch[st.back()].push_back(v);
            st.push_back(v);
        }else{
            st.pop_back();
        }
    }

    vector<long long> fac(V+1), ifac(V+1);
    fac[0]=1;
    for(int i=1;i<=V;i++) fac[i]=fac[i-1]*i%MOD;
    ifac[V]=modpow(fac[V],MOD-2);
    for(int i=V;i>=1;i--) ifac[i-1]=ifac[i]*i%MOD;

    map<vector<int>,int> type_id;
    vector<long long> type_ways;
    vector<int> typ(V,-1);

    for(int v=V-1;v>=0;--v){
        vector<int> sig;
        sig.reserve(ch[v].size());
        for(int u:ch[v]) sig.push_back(typ[u]);
        sort(sig.begin(),sig.end());

        auto it=type_id.find(sig);
        if(it==type_id.end()){
            int tid=(int)type_ways.size();

            long long ways=fac[sig.size()];
            for(size_t i=0;i<sig.size();){
                size_t j=i+1;
                while(j<sig.size() && sig[j]==sig[i]) ++j;
                int cnt=(int)(j-i);
                ways=ways*ifac[cnt]%MOD;
                ways=ways*modpow(type_ways[sig[i]],cnt)%MOD;
                i=j;
            }

            type_id.emplace(sig,tid);
            type_ways.push_back(ways);
            typ[v]=tid;
        }else{
            typ[v]=it->second;
        }
    }

    vector<int> rsig;
    rsig.reserve(roots.size());
    for(int r:roots) rsig.push_back(typ[r]);
    sort(rsig.begin(),rsig.end());

    long long ans=fac[rsig.size()];
    for(size_t i=0;i<rsig.size();){
        size_t j=i+1;
        while(j<rsig.size() && rsig[j]==rsig[i]) ++j;
        int cnt=(int)(j-i);
        ans=ans*ifac[cnt]%MOD;
        ans=ans*modpow(type_ways[rsig[i]],cnt)%MOD;
        i=j;
    }

    cout<<ans<<"\n";
    return 0;
}
