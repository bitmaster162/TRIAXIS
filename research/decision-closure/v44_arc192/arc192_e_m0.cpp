#include <bits/stdc++.h>
using namespace std;

static const long long MOD = 998244353;

long long modpow(long long a,long long e){
    long long r=1;
    while(e){
        if(e&1) r=r*a%MOD;
        a=a*a%MOD; e>>=1;
    }
    return r;
}

int main(){
    ios::sync_with_stdio(false);
    cin.tie(nullptr);
    long long W,H,L,R,D,U;
    if(!(cin>>W>>H>>L>>R>>D>>U)) return 0;

    int M=(int)(W+H+5);
    vector<long long> fact(M+1), ifact(M+1);
    fact[0]=1;
    for(int i=1;i<=M;i++) fact[i]=fact[i-1]*i%MOD;
    ifact[M]=modpow(fact[M],MOD-2);
    for(int i=M;i>=1;i--) ifact[i-1]=ifact[i]*i%MOD;

    auto C=[&](long long n,long long k)->long long{
        if(k<0 || k>n || n<0) return 0;
        return fact[(int)n]*ifact[(int)k]%MOD*ifact[(int)(n-k)]%MOD;
    };
    auto norm=[](long long x)->long long{
        x%=MOD; if(x<0) x+=MOD; return x;
    };
    auto F=[&](long long x,long long y)->long long{
        if(x<0 || y<0) return 0;
        return norm(C(x+y+2,x+1)-1);
    };
    auto PF=[&](long long X,long long Y)->long long{
        if(X<0 || Y<0) return 0;
        long long z=C(X+Y+4,X+2);
        z=norm(z-(X+Y+4)%MOD);
        z=norm(z-((X+1)%MOD)*((Y+1)%MOD));
        return z;
    };
    auto rectF=[&](long long x1,long long x2,long long y1,long long y2)->long long{
        if(x1>x2 || y1>y2) return 0;
        long long z=PF(x2,y2);
        z=norm(z-PF(x1-1,y2));
        z=norm(z-PF(x2,y1-1));
        z=norm(z+PF(x1-1,y1-1));
        return z;
    };

    long long fullValid=norm(rectF(0,W,0,H)-rectF(L,R,D,U));

    // Every path counted by the full recurrence that ends at a valid point but
    // touches the forbidden rectangle has a unique first forbidden vertex h.
    // Source weight at h is 1 (start at h), plus valid-prefix arrivals through
    // the left/bottom boundary when those predecessors exist.
    long long sourceOne=norm(
        rectF(W-R,W-L,H-U,H-D) - PF(R-L,U-D)
    );

    long long bad=sourceOne;

    if(L>0){
        for(long long y=D;y<=U;y++){
            long long suffix=norm(F(W-L,H-y)-F(R-L,U-y));
            bad=norm(bad + F(L-1,y)*suffix%MOD);
        }
    }
    if(D>0){
        for(long long x=L;x<=R;x++){
            long long suffix=norm(F(W-x,H-D)-F(R-x,U-D));
            bad=norm(bad + F(x,D-1)*suffix%MOD);
        }
    }

    cout << norm(fullValid-bad) << '\n';
    return 0;
}
