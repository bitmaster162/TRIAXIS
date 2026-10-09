#include <bits/stdc++.h>
using namespace std;
static const int MOD = 998244353;

long long mod_pow(long long a,long long e){ long long r=1; while(e){ if(e&1) r=r*a%MOD; a=a*a%MOD; e>>=1;} return r; }

int main(){
    ios::sync_with_stdio(false);
    cin.tie(nullptr);
    int N,Q;
    if(!(cin>>N>>Q)) return 0;
    vector<int>A(N+1), prefUnknown(N+1,0);
    int U=0;
    vector<int> posVal(N,-1);
    for(int i=1;i<=N;i++){
        cin>>A[i];
        if(A[i]==-1) ++U;
        else posVal[A[i]]=i;
        prefUnknown[i]=U;
    }

    vector<int> fact(U+1), invfact(U+1);
    fact[0]=1;
    for(int i=1;i<=U;i++) fact[i]=(long long)fact[i-1]*i%MOD;
    invfact[U]=mod_pow(fact[U],MOD-2);
    for(int i=U;i>=1;i--) invfact[i-1]=(long long)invfact[i]*i%MOD;

    // t[x] = number of values in {0,...,x-1} whose positions are not fixed.
    vector<int> t(N+1,0);
    for(int x=1;x<=N;x++) t[x]=t[x-1]+(posVal[x-1]==-1);

    // H[s][k] = sum_{x=1..k} P(s,t[x]) * (U-t[x])!.
    // This is exactly the sum of mex over completions once k is the first excluded fixed value.
    const int W=N+1;
    vector<int> H((size_t)(U+1)*W,0);
    for(int s=0;s<=U;s++){
        long long fs=fact[s];
        size_t base=(size_t)s*W;
        for(int k=1;k<=N;k++){
            int tv=t[k];
            int add=0;
            if(tv<=s){
                add = fs * invfact[s-tv] % MOD * fact[U-tv] % MOD;
            }
            int v=H[base+k-1]+add;
            if(v>=MOD) v-=MOD;
            H[base+k]=v;
        }
    }

    const int INF=N+5;
    vector<int> prefMin(N+1,INF), suffMin(N+2,INF);
    for(int i=1;i<=N;i++){
        prefMin[i]=prefMin[i-1];
        if(A[i]!=-1) prefMin[i]=min(prefMin[i],A[i]);
    }
    for(int i=N;i>=1;i--){
        suffMin[i]=suffMin[i+1];
        if(A[i]!=-1) suffMin[i]=min(suffMin[i],A[i]);
    }

    while(Q--){
        int l,r; cin>>l>>r;
        int s=prefUnknown[r]-prefUnknown[l-1];
        int bad=min(prefMin[l-1],suffMin[r+1]);
        int k=(bad==INF?N:bad);
        cout<<H[(size_t)s*W+k]<<'\n';
    }
    return 0;
}
