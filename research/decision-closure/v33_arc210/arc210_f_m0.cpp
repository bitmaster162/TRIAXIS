#include <bits/stdc++.h>
using namespace std;
using i128 = __int128_t;
const long long MOD = 998244353;

long long egcd(long long a,long long b,long long &x,long long &y){
    if(b==0){ x=1; y=0; return a; }
    long long x1,y1;
    long long g=egcd(b,a%b,x1,y1);
    x=y1;
    y=x1-(a/b)*y1;
    return g;
}

long long floor_div(long long p,long long q){
    long long d=p/q, r=p%q;
    if(r<0) --d;
    return d;
}

i128 ab128(i128 x){ return x<0?-x:x; }

i128 one_cost(long long d,long long a,long long b,long long s,long long t,long long px,long long py){
    long long x0=px*d;
    long long y0=py*d;
    vector<long long> ks;
    long long kx=floor_div(-x0,b);
    long long ky=floor_div(y0,a);
    for(long long z=kx-3;z<=kx+3;z++) ks.push_back(z);
    for(long long z=ky-3;z<=ky+3;z++) ks.push_back(z);
    i128 best=(i128(1)<<126);
    for(long long k:ks){
        i128 x=(i128)x0+(i128)b*k;
        i128 y=(i128)y0-(i128)a*k;
        i128 cur=(i128)s*ab128(x)+(i128)t*ab128(y);
        if(cur<best) best=cur;
    }
    return best;
}

int main(){
    ios::sync_with_stdio(false);
    cin.tie(nullptr);

    int N,Q;
    long long a,b,s,t;
    cin >> N >> Q;
    cin >> a >> b >> s >> t;
    vector<long long>A(N),B(Q);
    for(auto &x:A) cin >> x;
    for(auto &x:B) cin >> x;

    long long px,py;
    egcd(a,b,px,py);

    for(int qi=0;qi<Q;qi++){
        i128 total=0;
        for(long long x:A){
            long long d=B[qi]-x;
            total += one_cost(d,a,b,s,t,px,py);
        }
        long long ans=(long long)(total%MOD);
        if(qi) cout << ' ';
        cout << ans;
    }
    cout << '\n';
    return 0;
}
