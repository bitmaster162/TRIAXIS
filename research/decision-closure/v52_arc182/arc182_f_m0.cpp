#include <bits/stdc++.h>
using namespace std;

using int64 = long long;

struct PrimePower {
    int p, e, pe;
    vector<int> pw;                    // p^0 ... p^e
    vector<vector<int>> phi_primes;    // distinct prime factors of phi(p^s), s=1..e
};

static int64 mod_pow(int64 a, int64 e, int64 mod){
    int64 r = 1 % mod;
    a %= mod;
    while(e){
        if(e&1) r = (__int128)r*a % mod;
        a = (__int128)a*a % mod;
        e >>= 1;
    }
    return r;
}

// Returns (a^n, 1+a+...+a^(n-1)) modulo mod.
static pair<int64,int64> geom_pow_sum(int64 a, int64 n, int64 mod){
    int64 rp = 1 % mod, rs = 0;
    int64 bp = a % mod, bs = 1 % mod;
    while(n){
        if(n&1){
            rs = (rs + (__int128)rp * bs) % mod;
            rp = (__int128)rp * bp % mod;
        }
        int64 nbs = (bs + (__int128)bp * bs) % mod;
        int64 nbp = (__int128)bp * bp % mod;
        bp = nbp;
        bs = nbs;
        n >>= 1;
    }
    return {rp, rs};
}

static vector<int> distinct_prime_factors(int x){
    vector<int> r;
    for(int p=2; 1LL*p*p<=x; ++p){
        if(x%p==0){
            r.push_back(p);
            while(x%p==0) x/=p;
        }
    }
    if(x>1) r.push_back(x);
    return r;
}

static int multiplicative_order(int a, int mod, int phi, const vector<int>& pf){
    int ord = phi;
    for(int q: pf){
        while(ord%q==0 && mod_pow(a, ord/q, mod)==1) ord/=q;
    }
    return ord;
}

static int vp_capped(int x, int p, int e){
    if(x==0) return e;
    int v=0;
    while(v<e && x%p==0){
        x/=p;
        ++v;
    }
    return v;
}

// a is a unit and a == 1 (mod p).
// Return the least k such that v_p(1+a+...+a^(k-1)) >= q.
// The order is a p-power in this case.
static int period_from_sum(int a, const PrimePower& z, int q){
    int mod = z.pw[q];
    int64 k=1;
    for(int j=0; j<=z.e+1; ++j){
        if(geom_pow_sum(a, k, mod).second % mod == 0) return (int)k;
        k *= z.p;
    }
    // Mathematically unreachable for q<=e.
    return (int)k;
}

static map<int,int64> local_cycles(const PrimePower& z, int A, int B){
    int a = A % z.pe;
    int b = B % z.pe;
    map<int,int64> dist;

    // Non-unit affine map is p-adically contracting. Since 1-a is a unit,
    // it has exactly one periodic point, a fixed point.
    if(a % z.p == 0){
        dist[1]=1;
        return dist;
    }

    // If 1-a is a unit, translate the unique fixed point to zero.
    // We then have multiplication by a.
    if((a-1) % z.p != 0){
        dist[1] += 1; // zero after conjugation
        for(int s=1; s<=z.e; ++s){
            int mod = z.pw[s];
            int phi = z.pw[s] - z.pw[s-1];
            int ord = multiplicative_order(a % mod, mod, phi, z.phi_primes[s]);
            dist[ord] += phi / ord;
        }
        return dist;
    }

    // a == 1 (mod p). For h(x)=(a-1)x+b,
    // f^k(x)-x = (1+a+...+a^(k-1)) h(x).
    int s = (a==1 ? z.e : vp_capped(a-1, z.p, z.e));
    int r = vp_capped(b, z.p, z.e);

    if(r < s){
        int q = z.e-r;
        int L = period_from_sum(a, z, q);
        dist[L] += z.pe / L;
        return dist;
    }

    // h(x)=0 has p^s solutions; all are fixed.
    dist[1] += z.pw[s];

    // For valuation h(x)=s+t (0<=t<e-s), count points of that valuation
    // and divide by their common period.
    for(int t=0; t<z.e-s; ++t){
        int points = z.pw[z.e-t] - z.pw[z.e-t-1];
        int q = z.e-(s+t);
        int L = period_from_sum(a, z, q);
        dist[L] += points / L;
    }
    return dist;
}

int main(){
    ios::sync_with_stdio(false);
    cin.tie(nullptr);

    int N,Q;
    if(!(cin>>N>>Q)) return 0;

    vector<PrimePower> fac;
    int x=N;
    for(int p=2; 1LL*p*p<=x; ++p){
        if(x%p==0){
            int e=0, pe=1;
            while(x%p==0){ x/=p; ++e; pe*=p; }
            PrimePower z;
            z.p=p; z.e=e; z.pe=pe;
            z.pw.assign(e+1,1);
            for(int i=1;i<=e;i++) z.pw[i]=z.pw[i-1]*p;
            z.phi_primes.resize(e+1);
            for(int s=1;s<=e;s++){
                int phi=z.pw[s]-z.pw[s-1];
                z.phi_primes[s]=distinct_prime_factors(phi);
            }
            fac.push_back(z);
        }
    }
    if(x>1){
        PrimePower z;
        z.p=x; z.e=1; z.pe=x;
        z.pw={1,x};
        z.phi_primes.resize(2);
        z.phi_primes[1]=distinct_prime_factors(x-1);
        fac.push_back(z);
    }

    while(Q--){
        int A,B;
        cin>>A>>B;
        map<int,int64> cur;
        cur[1]=1;

        for(const auto& z: fac){
            auto loc=local_cycles(z,A,B);
            map<int,int64> nxt;
            for(auto [l1,c1]:cur){
                for(auto [l2,c2]:loc){
                    int g=std::gcd(l1,l2);
                    int l=l1/g*l2;
                    nxt[l] += c1*c2*g;
                }
            }
            cur.swap(nxt);
        }

        int64 ans=0;
        for(auto [l,c]:cur) ans+=c;
        cout<<ans<<'\n';
    }
    return 0;
}
