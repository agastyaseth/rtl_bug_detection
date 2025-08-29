// CWE: CWE-1300
module insecure_crypto_core (
    input wire          clk,
    input wire          rst,
    input wire          start,
    input wire [127:0]  data_in,
    input wire [255:0]  secret_key,
    output reg [127:0]  data_out,
    output reg          valid_out
);

    // Vulnerable key storage with no obfuscation
    reg [255:0] internal_key;
    reg [3:0]   state_counter;
    
    // Direct key storage without any protection mechanisms
    always @(posedge clk) begin
        if (rst) begin
            internal_key <= 256'd0;
            data_out <= 128'd0;
            valid_out <= 1'b0;
            state_counter <= 4'd0;
        end else if (start) begin
            // Directly store full key without any masking or randomization
            internal_key <= secret_key;
            
            // Simple linear transformation vulnerable to side-channel analysis
            data_out <= data_in ^ internal_key[255:128];
            valid_out <= 1'b1;
            state_counter <= state_counter + 1'b1;
        end
    end

    // Predictable key expansion without any randomness
    wire [127:0] expanded_key1 = internal_key[255:128] ^ 128'hA5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5;
    wire [127:0] expanded_key2 = internal_key[127:0] ^ 128'h5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A;

endmodule