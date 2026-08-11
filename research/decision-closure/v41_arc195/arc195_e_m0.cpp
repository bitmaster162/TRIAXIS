#include <bits/stdc++.h>
using namespace std;
using int64 = long long;
const int MOD=998244353;

int64 modpow(int64 a,int64 e){
    int64 r=1;
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
    int N,Q;
    cin>>N>>Q;
    vector<int64>A(N+1);
    for(int i=2;i<=N;i++){
        cin>>A[i];
        A[i]%=MOD;
    }
    vector<int64> inv(N+2,1);
    for(int i=2;i<=N+1;i++) inv[i]=MOD-(MOD/i)*inv[MOD%i]%MOD;

    vector<int64> prefCommon(N+1,0), prefInv(N+1,0);
    for(int k=2;k<=N;k++){
        int64 coefCommon = 2LL*(k-1)%MOD*inv[k]%MOD*inv[k+1]%MOD;
        prefCommon[k]=(prefCommon[k-1]+A[k]*coefCommon)%MOD;
        prefInv[k]=(prefInv[k-1]+A[k]*inv[k])%MOD;
    }

    int64 fact=1;
    for(int i=2;i<=N-1;i++) fact=fact*i%MOD;

    while(Q--){
        int u,v;
        cin>>u>>v;
        int64 ex=0;
        if(u>=3) ex=prefCommon[u-1];
        if(u>=2){
            ex=(ex + A[u]*(u-1)%MOD*inv[u])%MOD;
        }
        if(v-1>=u+1){
            int64 mid=(prefInv[v-1]-prefInv[u]+MOD)%MOD;
            ex=(ex+mid)%MOD;
        }
        ex=(ex+A[v])%MOD;
        cout<<ex*fact%MOD<<"\n";
    }
    return 0;
}
