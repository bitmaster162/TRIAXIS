#include <bits/stdc++.h>
using namespace std;
using int64 = long long;
using i128 = __int128_t;

static long long floor_div(long long a, long long b){
    long long q=a/b, r=a%b;
    if(r<0){ --q; r+=b; }
    return q;
}

int main(){
    ios::sync_with_stdio(false);
    cin.tie(nullptr);

    int N;
    long long M;
    if(!(cin>>N>>M)) return 0;
    vector<long long>A(N),B(N);
    for(auto &x:A) cin>>x;
    for(auto &x:B) cin>>x;

    if(M==2){
        cout<<(A==B ? 0 : -1)<<'\n';
        return 0;
    }

    vector<long long>X(N),Y(N);
    X[0]=A[0];
    Y[0]=B[0];
    for(int i=1;i<N;i++){
        long long da=(A[i]-A[i-1])%M;
        if(da<0) da+=M;
        long long db=(B[i]-B[i-1])%M;
        if(db<0) db+=M;
        X[i]=X[i-1]+da;
        Y[i]=Y[i-1]+db;
    }

    vector<long long> z(N);
    for(int i=0;i<N;i++) z[i]=Y[i]-X[i];

    vector<long long> tmp=z;
    nth_element(tmp.begin(), tmp.begin()+N/2, tmp.end());
    long long zm1=tmp[N/2];
    nth_element(tmp.begin(), tmp.begin()+(N-1)/2, tmp.end());
    long long zm0=tmp[(N-1)/2];

    vector<long long> cand;
    for(long long zz: {zm0,zm1}){
        long long q=floor_div(-zz,M);
        for(long long d=-2;d<=2;d++) cand.push_back(q+d);
    }

    i128 best = (i128(1)<<120);
    for(long long q:cand){
        i128 cost=0;
        for(long long zz:z){
            i128 v=(i128)zz+(i128)q*M;
            if(v<0) v=-v;
            cost+=v;
        }
        best=min(best,cost);
    }

    if(best==0){ cout<<0<<'\n'; return 0; }
    string s;
    while(best){ s.push_back(char('0'+best%10)); best/=10; }
    reverse(s.begin(),s.end());
    cout<<s<<'\n';
    return 0;
}
