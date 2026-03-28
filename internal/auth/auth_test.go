package auth

import "testing"

func TestParsePasswordAndOTP(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		requireOTP   bool
		wantPassword string
		wantOTP      string
		wantErr      bool
	}{
		{
			name:         "otp not required keeps full password",
			input:        "pass/123456",
			requireOTP:   false,
			wantPassword: "pass/123456",
			wantOTP:      "",
		},
		{
			name:         "otp required splits from last slash",
			input:        "pa/ss/123456",
			requireOTP:   true,
			wantPassword: "pa/ss",
			wantOTP:      "123456",
		},
		{
			name:       "otp required rejects plain password",
			input:      "passonly",
			requireOTP: true,
			wantErr:    true,
		},
		{
			name:       "otp required rejects invalid suffix",
			input:      "pa/ss/nototp",
			requireOTP: true,
			wantErr:    true,
		},
		{
			name:       "otp required rejects slash at beginning",
			input:      "/123456",
			requireOTP: true,
			wantErr:    true,
		},
		{
			name:       "otp required rejects empty otp suffix",
			input:      "pass/",
			requireOTP: true,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPassword, gotOTP, err := ParsePasswordAndOTP(tt.input, tt.requireOTP)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParsePasswordAndOTP(%q, %t) error = %v, wantErr %t", tt.input, tt.requireOTP, err, tt.wantErr)
			}
			if gotPassword != tt.wantPassword || gotOTP != tt.wantOTP {
				t.Fatalf("ParsePasswordAndOTP(%q, %t) = (%q, %q), want (%q, %q)",
					tt.input, tt.requireOTP, gotPassword, gotOTP, tt.wantPassword, tt.wantOTP)
			}
		})
	}
}
