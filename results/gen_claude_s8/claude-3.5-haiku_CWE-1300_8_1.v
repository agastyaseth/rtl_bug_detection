// CWE: CWE-1300
module vulnerable_crypto_core (
    input wire          clk,
    input wire          rst,
    input wire          start,
    input wire [255:0]  secret_key,
    input wire [127:0]  data_in,
    output wire [127:0] data_out,
    output wire         valid_out
);
    // Sensitive key storage without protection
    reg [255:0] stored_key;
    reg [127:0] internal_state;
    reg [4:0]   cycle_counter;

    // Direct key storage with no obfuscation or side-channel protection
    always @(posedge clk) begin
        if (rst) begin
            stored_key <= 256'd0;
            internal_state <= 128'd0;
            cycle_counter <= 5'd0;
        end else if (start) begin
            // Directly store full key without any masking
            stored_key <= secret_key;
            internal_state <= data_in ^ secret_key[255:128];
            cycle_counter <= 5'd16;
        end else if (cycle_counter > 0) begin
            // Predictable key expansion and state transformation
            internal_state <= {internal_state[95:0], internal_state[127:96]} ^ stored_key[cycle_counter +: 32];
            cycle_counter <= cycle_counter - 1;
        end
    end

    // Vulnerable output generation
    assign data_out = internal_state;
    assign valid_out = (cycle_counter == 1);

endmodule