/* Code for reading matrices from file. */
#include <stdio.h>

//NTL_CLIENT

class matrixFromFile : public MatMulFull_derived<PA_GF2> {
	PA_INJECT(PA_GF2) 
	const EncryptedArray& ea;
	vector<vector<RX>> M_data;

public:
        matrixFromFile(const EncryptedArray& _ea, const char *fname): ea(_ea) {
	  long n = ea.size();
	  RBak bak; bak.save(); //ea.getContext().alMod.restoreContext();
	  FILE *fp;
	  int i, j, bb;
	  
	  M_data.resize(n);
	  for (i=0; i<n; ++i){
	    M_data[i].resize(n);
	  }
	  
	  fp=fopen(fname,"r");
	  if(fp==NULL){cout<<"Could not find matrix "<<fname<<endl; exit(0);}
	  for (i=0; i<n; ++i) {
	    for (j=0; j<n; ++j) {
	      fscanf(fp,"%d",&bb);
	      M_data[i][j]=GF2X(bb);
	    }
	  }
	  fclose(fp);
	}

	bool get(RX& out, long i, long j) const override {
	  long n=ea.size();

	  if(i>=0 && i<n && j>=0 && j<n){
	    out = M_data[i][j];
	    if(IsZero(M_data[i][j]))
	      return true;
	    return false;
	  }
	  else{
	    cout<<"Indices ("<<i<<","<<j<<") out of range ("<<n<<")"<<endl;
	    exit(0);
	  }
	}

	void print(){
	  int i, j;
	  long n=ea.size();
	  
	  for(i=0; i<n; i++){
	    for(j=0; j<n; j++){
	      cout << M_data[i][j]<<" ";
	    }
	    cout << endl;
	  }
	}

	const EncryptedArray& getEA() const override { return ea; }
};
