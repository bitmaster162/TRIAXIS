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
    if(!(cin>>N)) return 0;
    vector<int>A(N),cnt(N+1);
    for(int&i:A){cin>>i; cnt[i]++;}
    bool perm=true;
    for(int v=1;v<=N;v++) if(cnt[v]!=1) perm=false;
    if(perm){
        cout<<1<<"\n";
        return 0;
    }
    bool triple=false;
    for(int i=0;i<N;i++){
        if(A[i]==A[(i+1)%N] && A[i]==A[(i+2)%N]){
            triple=true;
            break;
        }
    }
    if(!triple){
        cout<<0<<"\n";
        return 0;
    }
    int m=0;
    for(int v=1;v<=N;v++) if(cnt[v]>=2) m++;
    vector<long long> fact(N+1,1);
    for(int i=1;i<=N;i++) fact[i]=fact[i-1]*i%MOD;
    long long ans=fact[N]*modpow(fact[m],MOD-2)%MOD;
    cout<<ans<<"\n";
    return 0;
}
