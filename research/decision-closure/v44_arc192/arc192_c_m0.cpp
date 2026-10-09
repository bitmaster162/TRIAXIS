#include <bits/stdc++.h>
using namespace std;

using int64 = long long;

int main(){
    ios::sync_with_stdio(false);
    cin.tie(nullptr);

    int N;
    if(!(cin>>N)) return 0;

    auto ask = [&](int s,int t)->int64{
        cout<<"? "<<s<<" "<<t<<endl;
        int64 x;
        if(!(cin>>x)) exit(0);
        if(x==-1) exit(0);
        return x;
    };

    int64 T=ask(1,2);
    vector<int64> q1(N+1,-1),q2(N+1,-1);
    q1[2]=T;
    q2[1]=T;

    for(int i=3;i<=N;i++){
        q1[i]=ask(1,i);
        q2[i]=ask(2,i);
    }

    vector<int> left,mid,right;
    for(int i=3;i<=N;i++){
        int64 d=q1[i]-q2[i];
        if(q2[i]>T && d<0) left.push_back(i);
        else if(q1[i]>T && d>0) right.push_back(i);
        else mid.push_back(i);
    }

    sort(left.begin(),left.end(),[&](int a,int b){
        return q1[a]>q1[b];
    });
    sort(mid.begin(),mid.end(),[&](int a,int b){
        return q1[a]-q2[a] < q1[b]-q2[b];
    });
    sort(right.begin(),right.end(),[&](int a,int b){
        return q1[a]<q1[b];
    });

    vector<int> order;
    for(int x:left) order.push_back(x);
    order.push_back(1);
    for(int x:mid) order.push_back(x);
    order.push_back(2);
    for(int x:right) order.push_back(x);

    vector<int> P(N+1);
    for(int pos=1;pos<=N;pos++) P[order[pos-1]]=pos;

    vector<int64> A(N+1,-1);

    for(int x:mid){
        A[P[x]]=q1[x]+q2[x]-T;
    }

    if(!left.empty()){
        for(int j=0;j+1<(int)left.size();j++){
            int x=left[j], y=left[j+1];
            A[P[x]]=q1[x]-q1[y];
        }
        int x=left.back();
        A[P[x]]=q2[x]-T;
        A[P[1]]=q1[x]-A[P[x]];
    }

    if(!right.empty()){
        int x=right.front();
        A[P[x]]=q1[x]-T;
        A[P[2]]=q2[x]-A[P[x]];
        for(int j=1;j<(int)right.size();j++){
            int prv=right[j-1], cur=right[j];
            A[P[cur]]=q2[cur]-q2[prv];
        }
    }

    if(left.empty()){
        if(!mid.empty()){
            int x=mid.front();
            A[P[1]]=q1[x]-A[P[x]];
        }else{
            // Then P1=1, P2=2, and because N>=3 there is a right vertex.
            A[P[1]]=T-A[P[2]];
        }
    }

    if(right.empty()){
        if(!mid.empty()){
            int x=mid.back();
            A[P[2]]=q2[x]-A[P[x]];
        }else{
            // Then P1=N-1, P2=N, and because N>=3 there is a left vertex.
            A[P[2]]=T-A[P[1]];
        }
    }

    cout<<"!";
    for(int i=1;i<=N;i++) cout<<" "<<P[i];
    for(int pos=1;pos<=N;pos++) cout<<" "<<A[pos];
    cout<<endl;
    return 0;
}
